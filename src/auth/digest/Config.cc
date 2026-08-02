/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 29    Authenticator */

/* The functions in this file handle authentication.
 * They DO NOT perform access control or auditing.
 * See acl.c for access control and client_side.c for auditing */

#include "squid.h"
#include "auth/CredentialsCache.h"
#include "auth/digest/Config.h"
#include "auth/digest/Scheme.h"
#include "auth/digest/User.h"
#include "auth/digest/UserRequest.h"
#include "auth/Gadgets.h"
#include "auth/State.h"
#include "auth/toUtf.h"
#include "base/LookupTable.h"
#include "base/Random.h"
#include "cache_cf.h"
#include "event.h"
#include "helper.h"
#include "HttpHeaderTools.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "md5.h"
#include "mgr/Registration.h"
#include "rfc2617.h"
#include "sbuf/SBuf.h"
#include "sbuf/StringConvert.h"
#include "Store.h"
#include "StrList.h"
#include "wordlist.h"

/* digest_nonce_h still uses explicit alloc()/freeOne() MemPool calls.
 * XXX: convert to MEMPROXY_CLASS() API
 */
#include "mem/Allocator.h"
#include "mem/Pool.h"

static AUTHSSTATS authenticateDigestStats;

Helper::ClientPointer digestauthenticators;

static hash_table *digest_nonce_cache;

static int authdigest_initialised = 0;
static Mem::Allocator *digest_nonce_pool = nullptr;

enum http_digest_attr_type {
    DIGEST_USERNAME,
    DIGEST_REALM,
    DIGEST_QOP,
    DIGEST_ALGORITHM,
    DIGEST_URI,
    DIGEST_NONCE,
    DIGEST_NC,
    DIGEST_CNONCE,
    DIGEST_RESPONSE,
    DIGEST_INVALID_ATTR
};

static const auto &
digestFieldsLookupTable()
{
    static const LookupTable<http_digest_attr_type>::Record DigestAttrs[] = {
        {"username", DIGEST_USERNAME},
        {"realm", DIGEST_REALM},
        {"qop", DIGEST_QOP},
        {"algorithm", DIGEST_ALGORITHM},
        {"uri", DIGEST_URI},
        {"nonce", DIGEST_NONCE},
        {"nc", DIGEST_NC},
        {"cnonce", DIGEST_CNONCE},
        {"response", DIGEST_RESPONSE},
        {nullptr, DIGEST_INVALID_ATTR}
    };
    static const auto table = new LookupTable<http_digest_attr_type>(DIGEST_INVALID_ATTR, DigestAttrs);
    return *table;
}

/* Destination capacity contract for the Digest credential fields parsed by
 * Auth::Digest::Config::decode() below.
 *
 * decode() runs on unauthenticated input, before any credential is verified and
 * before the authentication helper is consulted. Each field value is therefore
 * checked against the capacity of its destination before being copied there:
 * the table below declares that capacity per field, and decode() consults it
 * once per recognized field, before dispatching to the case that copies the
 * value, so the check belongs to the extraction loop rather than to nine
 * separate switch cases. A new http_digest_attr_type enumerator cannot reach a
 * copy unguarded: without a matching capacity row the static_assert() on
 * DigestFieldCapacitiesAreWellFormed() fails to compile, and without a case of
 * its own it fails the exhaustive switch, which deliberately has no default
 * label.
 */
namespace {

enum class DigestLengthRule {
    exact, ///< the capacity is the only length the field admits
    atMost, ///< the capacity is the greatest length the field admits
    /// the greatest length the field admits is String::RawSizeMaxXXX(), which
    /// the row names instead of storing because it is a static member function
    /// rather than a constant expression
    rawSizeMax,
    any ///< the field declares no length of its own; only the universal bound applies
};

class DigestFieldCapacity
{
public:
    http_digest_attr_type id;
    DigestLengthRule rule;
    /// the value length in bytes that DigestLengthRule::exact and
    /// DigestLengthRule::atMost compare against; the remaining rules name their
    /// limit rather than storing one and leave this zero
    String::size_type capacity;
};

/// The length contract of every Digest credential field, indexed by
/// http_digest_attr_type. A field whose accepted values have a fixed or an
/// enumerated length carries that exact or maximum length, so that its row
/// repeats, earlier, a length the validation below already requires. A field
/// whose accepted values have no such length carries a maximum this contract
/// imposes, with the reason recorded on the row itself. A field which nothing
/// narrows at all says so by naming the shared String::RawSizeMaxXXX() bound as
/// its own limit rather than adding a narrower number that nothing justifies.
/// DigestFieldLengthOk() applies the universal String::RawSizeMaxXXX() bound to
/// every field before consulting its row here, so a row restates that bound only
/// where it is also the field's own declared limit.
constexpr DigestFieldCapacity DigestFieldCapacities[] = {
    /* The username and the realm are the two fields this parser hands to the
     * authentication helper, and the helper request line is what makes a long
     * value harmful rather than merely large.
     * Auth::Digest::UserRequest::startHelperLookup()
     * (src/auth/digest/UserRequest.cc:274-297) composes that line into a
     * char buf[8192] with snprintf(buf, 8192, "\"%s\":\"%s\"\n", username,
     * realm), or, when "auth_param digest key_extras" is configured, with
     * snprintf(buf, 8192, "\"%s\":\"%s\" %s\n", username, realm, keyExtras).
     * snprintf() writes at most 8191 characters and a terminator, so a longer
     * line loses its trailing bytes, and the byte it loses first is the newline
     * which frames the request: truncation may therefore leave the helper
     * waiting for a line it never receives, or run the request into whatever is
     * written after it. Truncating either field is therefore not benign, and
     * 1024 bytes each keep the two of them within 2048 of the 8192 available.
     * That does not by itself guarantee that the whole line fits, because the
     * framing bytes and any configured key_extras expansion share the same
     * buffer, and the length of that expansion is an operator's configuration
     * choice (src/cf.data.pre:647-669, assembled by
     * Auth::UserRequest::helperRequestKeyExtras(),
     * src/auth/UserRequest.cc:560-574) which this parser neither sees nor
     * bounds. The limit also bounds what one unauthenticated request can make
     * this parser allocate for either field. The check runs on the arriving
     * value and again on the transcoded value, which is what gets copied. */
    {DIGEST_USERNAME, DigestLengthRule::atMost, 1024},

    /* The realm is the other field on the helper request line described above,
     * and the same 1024 bytes bound what it contributes to it. A client echoes
     * the value Auth::Digest::Config::fixHeader() below issued from the
     * configured "auth_param digest realm"; the validation below never compares
     * the two, and the helper lookup is keyed on the echo, so this row alone
     * holds it to a length that line can carry. Those 1024 bytes are this
     * contract's share of the 8192 rather than the length at which snprintf()
     * truncates.
     * Configuration does not impose this limit: the "realm" branch of
     * Auth::SchemeConfig::parse() (src/auth/SchemeConfig.cc) accepts a realm of
     * any length, and fixHeader() advertises whatever it accepted. A realm
     * configured longer than 1024 bytes is therefore issued in the challenge but
     * rejected here when a client echoes it, which leaves such a realm unusable
     * rather than merely long. */
    {DIGEST_REALM, DigestLengthRule::atMost, 1024},

    /* The validation below accepts only a qop equal to QOP_AUTH, which
     * src/auth/digest/Config.h:101 defines as the four bytes "auth", so a
     * longer value is already rejected there; 8 leaves headroom for the
     * existing "Invalid qop option received" diagnostic to report near misses
     * instead of being pre-empted by a length rejection */
    {DIGEST_QOP, DigestLengthRule::atMost, 8},

    /* the validation below accepts only "MD5" and "MD5-sess", the longer of
     * which is 8 bytes, so a longer value is already rejected there */
    {DIGEST_ALGORITHM, DigestLengthRule::atMost, 8},

    /* Request targets are legitimately long, and unlike the fields above
     * nothing further down narrows this one: the validation below rejects only
     * an empty uri. Its limit is therefore String::RawSizeMaxXXX(), which
     * src/SquidString.h:74-76 defines as the conservative ceiling for raw input
     * that later processing may grow -- a third of the String::SizeMaxXXX()
     * absolute limit, not that limit itself -- and which this codebase already
     * applies to attacker-supplied input elsewhere (src/http.cc:1972,
     * src/http/one/RequestParser.cc:143). The row names that bound, rather than
     * storing a narrower number of its own, so that this field declares the
     * limit it is held to instead of leaving it to be inferred from the absence
     * of one. Note that a credential does not usually reach this length:
     * HttpHeaderEntry::parse() (src/HttpHeader.cc:1619) refuses a header field
     * value longer than 65534 bytes, and it does so before these credentials are
     * split into fields, so a uri that long is normally answered as a malformed
     * header rather than as a disallowed field length. The bound is still stated
     * here, because a limit which another parser happens to apply first is not
     * this parser's to rely on. */
    {DIGEST_URI, DigestLengthRule::rawSizeMax, 0},

    /* Squid accepts only a nonce it generated itself, and
     * authDigestNonceEncode() below builds every one of those with
     * xcalloc(sizeof(HASHHEX), 1) and CvtHex(), that is with exactly HASHHEXLEN
     * bytes (include/rfc2617.h:28-29). authenticateDigestNonceFindNonce() below
     * therefore fails to match a value of any other length, however long it is;
     * 256 is eightfold headroom above the 32 bytes that can match */
    {DIGEST_NONCE, DigestLengthRule::atMost, 256},

    /* RFC 7616 section 3.4 makes the nonce-count 8 hexadecimal digits, the
     * validation below rejects any nc whose length is not 8, and the
     * destination is the fixed char nc[9] of
     * src/auth/digest/UserRequest.h:52; the DIGEST_NC case below ties this row
     * to sizeof(nc) with a static_assert() so that the limit and the buffer it
     * protects cannot drift apart */
    {DIGEST_NC, DigestLengthRule::exact, 8},

    /* A client-chosen opaque value which nothing else constrains: the validation
     * below rejects only an empty cnonce, and
     * src/auth/digest/UserRequest.cc:100-107 passes whatever arrived to
     * DigestCalcHA1() and DigestCalcResponse(), which hash it without a length
     * limit. RFC 7616 section 3.4 fixes no length for it either, so 256 is a
     * limit this contract imposes rather than one a check further down already
     * implies, and it is what keeps this pre-authentication copy finite. It is
     * eightfold the HASHHEXLEN bytes (include/rfc2617.h:28-29) of the nonce the
     * cnonce accompanies, that being the only comparable length this scheme
     * fixes */
    {DIGEST_CNONCE, DigestLengthRule::atMost, 256},

    /* include/rfc2617.h:28-29 fix an MD5 hexadecimal digest at HASHHEXLEN
     * bytes (typedef char HASHHEX[HASHHEXLEN + 1]), and the validation below
     * already rejects any response whose length is not that */
    {DIGEST_RESPONSE, DigestLengthRule::exact, HASHHEXLEN},

    /* attributes that digestFieldsLookupTable() does not recognize are reported
     * and skipped before the extraction switch below, so nothing is copied for
     * them and no destination capacity applies */
    {DIGEST_INVALID_ATTR, DigestLengthRule::any, 0}
};

/**
 * Whether DigestFieldCapacities[] still describes http_digest_attr_type
 * exactly. Checked at compile time so that extending the enumeration without
 * declaring the new field's destination capacity is a build failure rather than
 * a silently unguarded copy.
 *
 \retval true  the table holds one row per enumerator, each stored at the index
               of the enumerator it describes and each carrying a capacity only
               if its rule compares against one
 \retval false the table and the enumeration have drifted apart, or a row's rule
               and capacity disagree
 */
constexpr bool
DigestFieldCapacitiesAreWellFormed()
{
    if (sizeof(DigestFieldCapacities) / sizeof(DigestFieldCapacities[0]) != static_cast<size_t>(DIGEST_INVALID_ATTR) + 1)
        return false;
    for (auto i = 0; i <= DIGEST_INVALID_ATTR; ++i) {
        const auto &limit = DigestFieldCapacities[i];
        if (static_cast<int>(limit.id) != i)
            return false;
        /* a rule which compares against the stored capacity needs one, and a
         * rule which names its limit instead must not also store a second one
         * that nothing reads */
        const auto comparesAgainstCapacity = (limit.rule == DigestLengthRule::exact || limit.rule == DigestLengthRule::atMost);
        if (comparesAgainstCapacity != (limit.capacity > 0))
            return false;
    }
    return true;
}

static_assert(DigestFieldCapacitiesAreWellFormed());

/**
 * Whether a Digest credential field value of the given byte length may be
 * copied into the destination that Auth::Digest::Config::decode() keeps for
 * that field. The length must satisfy both the universal
 * String::RawSizeMaxXXX() bound and the DigestFieldCapacities[] rule of its
 * field, which for DIGEST_NC and DIGEST_RESPONSE is an exact length rather than
 * a maximum. decode() calls this before dispatching to the case which performs
 * the copy, so that a value of a length the destination does not admit is
 * rejected without being copied, and reports the rejection here so that all
 * callers share one diagnostic.
 *
 * Rejection is not fatal, and it is not signalled by the absence of the field:
 * decode() records it explicitly and then fails the whole credentials through
 * authDigestLogUsername(), because a field left absent is indistinguishable
 * from one that was never sent and the optional fields would otherwise be
 * defaulted rather than rejected.
 *
 \param type[in]    the credential field being extracted, as resolved by
                    digestFieldsLookupTable(); any http_digest_attr_type
                    enumerator is accepted
 \param keyName[in] the field name as it appeared in the credentials, used only
                    for reporting
 \param length[in]  the length in bytes of the value decode() is about to copy;
                    for DIGEST_USERNAME decode() submits the length as it
                    arrived and, when transcoding to UTF-8 rewrites the value,
                    the length transcoding produced, which can be greater
 \retval true  the destination admits a value of this length
 \retval false the length exceeds the universal String::RawSizeMaxXXX() bound or
               this field's declared capacity, or differs from the single length
               a fixed-length field admits, and the value must not be copied
 */
bool
DigestFieldLengthOk(const http_digest_attr_type type, const SBuf &keyName, const String::size_type length)
{
    /* the universal bound comes first so that it holds whatever a field's own
     * rule turns out to be; it is applied here rather than in the table above
     * because String::RawSizeMaxXXX() is a static member function, not a
     * constexpr constant, which is also why a field whose capacity is exactly
     * that bound names it in its rule instead of storing it as a number */
    auto fits = length <= String::RawSizeMaxXXX();

    if (fits) {
        // DigestFieldCapacitiesAreWellFormed() guarantees a row for every
        // enumerator, and digestFieldsLookupTable() only ever yields enumerators
        const auto &limit = DigestFieldCapacities[type];
        switch (limit.rule) {
        case DigestLengthRule::exact:
            fits = (length == limit.capacity);
            break;
        case DigestLengthRule::atMost:
            fits = (length <= limit.capacity);
            break;
        case DigestLengthRule::rawSizeMax:
            fits = (length <= String::RawSizeMaxXXX());
            break;
        case DigestLengthRule::any:
            break;
        }
    }

    if (!fits)
        debugs(29, 3, "Rejecting Digest credential field " << keyName << " with a disallowed value length of " << length << " bytes");

    return fits;
}

} // namespace

/*
 *
 * Nonce Functions
 *
 */

static void authenticateDigestNonceCacheCleanup(void *data);
static digest_nonce_h *authenticateDigestNonceFindNonce(const char *noncehex);
static void authenticateDigestNonceDelete(digest_nonce_h * nonce);
static void authenticateDigestNonceSetup(void);
static void authDigestNonceEncode(digest_nonce_h * nonce);
static void authDigestNonceLink(digest_nonce_h * nonce);
static void authDigestNonceUserUnlink(digest_nonce_h * nonce);

static void
authDigestNonceEncode(digest_nonce_h * nonce)
{
    if (!nonce)
        return;

    if (nonce->key)
        xfree(nonce->key);

    SquidMD5_CTX Md5Ctx;
    HASH H;
    SquidMD5Init(&Md5Ctx);
    SquidMD5Update(&Md5Ctx, reinterpret_cast<const uint8_t *>(&nonce->noncedata), sizeof(nonce->noncedata));
    SquidMD5Final(reinterpret_cast<uint8_t *>(H), &Md5Ctx);

    nonce->key = xcalloc(sizeof(HASHHEX), 1);
    CvtHex(H, static_cast<char *>(nonce->key));
}

digest_nonce_h *
authenticateDigestNonceNew(void)
{
    digest_nonce_h *newnonce = static_cast < digest_nonce_h * >(digest_nonce_pool->alloc());

    /* NONCE CREATION - NOTES AND REASONING. RBC 20010108
     * === EXCERPT FROM RFC 2617 ===
     * The contents of the nonce are implementation dependent. The quality
     * of the implementation depends on a good choice. A nonce might, for
     * example, be constructed as the base 64 encoding of
     *
     * time-stamp H(time-stamp ":" ETag ":" private-key)
     *
     * where time-stamp is a server-generated time or other non-repeating
     * value, ETag is the value of the HTTP ETag header associated with
     * the requested entity, and private-key is data known only to the
     * server.  With a nonce of this form a server would recalculate the
     * hash portion after receiving the client authentication header and
     * reject the request if it did not match the nonce from that header
     * or if the time-stamp value is not recent enough. In this way the
     * server can limit the time of the nonce's validity. The inclusion of
     * the ETag prevents a replay request for an updated version of the
     * resource.  (Note: including the IP address of the client in the
     * nonce would appear to offer the server the ability to limit the
     * reuse of the nonce to the same client that originally got it.
     * However, that would break proxy farms, where requests from a single
     * user often go through different proxies in the farm. Also, IP
     * address spoofing is not that hard.)
     * ====
     *
     * Now for my reasoning:
     * We will not accept a unrecognised nonce->we have all recognisable
     * nonces stored. If we send out unique encodings we guarantee
     * that a given nonce applies to only one user (barring attacks or
     * really bad timing with expiry and creation).  Using a random
     * component in the nonce allows us to loop to find a unique nonce.
     * We use H(nonce_data) so the nonce is meaningless to the receiver.
     * So our nonce looks like hex(H(timestamp,randomdata))
     * And even if our randomness is not very random we don't really care
     * - the timestamp also guarantees local uniqueness in the input to
     * the hash function.
     */
    static std::mt19937 mt(RandomSeed32());
    static std::uniform_int_distribution<uint32_t> newRandomData;

    /* create a new nonce */
    newnonce->nc = 0;
    newnonce->flags.valid = true;
    newnonce->noncedata.creationtime = current_time.tv_sec;
    newnonce->noncedata.randomdata = newRandomData(mt);

    authDigestNonceEncode(newnonce);

    // ensure temporal uniqueness by checking for existing nonce
    while (authenticateDigestNonceFindNonce((char const *) (newnonce->key))) {
        /* create a new nonce */
        newnonce->noncedata.randomdata = newRandomData(mt);
        authDigestNonceEncode(newnonce);
    }

    hash_join(digest_nonce_cache, newnonce);
    /* the cache's link */
    authDigestNonceLink(newnonce);
    newnonce->flags.incache = true;
    debugs(29, 5, "created nonce " << newnonce << " at " << newnonce->noncedata.creationtime);
    return newnonce;
}

static void
authenticateDigestNonceDelete(digest_nonce_h * nonce)
{
    if (nonce) {
        assert(nonce->references == 0);
        assert(!nonce->flags.incache);

        safe_free(nonce->key);

        digest_nonce_pool->freeOne(nonce);
    }
}

static void
authenticateDigestNonceSetup(void)
{
    if (!digest_nonce_pool)
        digest_nonce_pool = memPoolCreate("Digest Scheme nonce's", sizeof(digest_nonce_h));

    if (!digest_nonce_cache) {
        digest_nonce_cache = hash_create((HASHCMP *) strcmp, 7921, hash_string);
        assert(digest_nonce_cache);
        eventAdd("Digest nonce cache maintenance", authenticateDigestNonceCacheCleanup, nullptr, static_cast<Auth::Digest::Config*>(Auth::SchemeConfig::Find("digest"))->nonceGCInterval, 1);
    }
}

void
authenticateDigestNonceShutdown(void)
{
    /*
     * We empty the cache of any nonces left in there.
     */
    digest_nonce_h *nonce;

    if (digest_nonce_cache) {
        debugs(29, 2, "Shutting down nonce cache");
        hash_first(digest_nonce_cache);

        while ((nonce = ((digest_nonce_h *) hash_next(digest_nonce_cache)))) {
            assert(nonce->flags.incache);
            authDigestNoncePurge(nonce);
        }
    }

    debugs(29, 2, "Nonce cache shutdown");
}

static void
authenticateDigestNonceCacheCleanup(void *)
{
    /*
     * We walk the hash by noncehex as that is the unique key we
     * use.  For big hash tables we could consider stepping through
     * the cache, 100/200 entries at a time. Lets see how it flies
     * first.
     */
    digest_nonce_h *nonce;
    debugs(29, 3, "Cleaning the nonce cache now");
    debugs(29, 3, "Current time: " << current_time.tv_sec);
    hash_first(digest_nonce_cache);

    while ((nonce = ((digest_nonce_h *) hash_next(digest_nonce_cache)))) {
        debugs(29, 3, "nonce entry  : " << nonce << " '" << (char *) nonce->key << "'");
        debugs(29, 4, "Creation time: " << nonce->noncedata.creationtime);

        if (authDigestNonceIsStale(nonce)) {
            debugs(29, 4, "Removing nonce " << (char *) nonce->key << " from cache due to timeout.");
            assert(nonce->flags.incache);
            /* invalidate nonce so future requests fail */
            nonce->flags.valid = false;
            /* if it is tied to a auth_user, remove the tie */
            authDigestNonceUserUnlink(nonce);
            authDigestNoncePurge(nonce);
        }
    }

    debugs(29, 3, "Finished cleaning the nonce cache.");

    if (static_cast<Auth::Digest::Config*>(Auth::SchemeConfig::Find("digest"))->active())
        eventAdd("Digest nonce cache maintenance", authenticateDigestNonceCacheCleanup, nullptr, static_cast<Auth::Digest::Config*>(Auth::SchemeConfig::Find("digest"))->nonceGCInterval, 1);
}

static void
authDigestNonceLink(digest_nonce_h * nonce)
{
    assert(nonce != nullptr);
    ++nonce->references;
    assert(nonce->references != 0); // no overflows
    debugs(29, 9, "nonce '" << nonce << "' now at '" << nonce->references << "'.");
}

void
authDigestNonceUnlink(digest_nonce_h * nonce)
{
    assert(nonce != nullptr);

    if (nonce->references > 0) {
        -- nonce->references;
    } else {
        debugs(29, DBG_IMPORTANT, "Attempt to lower nonce " << nonce << " refcount below 0!");
    }

    debugs(29, 9, "nonce '" << nonce << "' now at '" << nonce->references << "'.");

    if (nonce->references == 0)
        authenticateDigestNonceDelete(nonce);
}

const char *
authenticateDigestNonceNonceHex(const digest_nonce_h * nonce)
{
    if (!nonce)
        return nullptr;

    return (char const *) nonce->key;
}

static digest_nonce_h *
authenticateDigestNonceFindNonce(const char *noncehex)
{
    digest_nonce_h *nonce = nullptr;

    if (noncehex == nullptr)
        return nullptr;

    debugs(29, 9, "looking for noncehex '" << noncehex << "' in the nonce cache.");

    nonce = static_cast < digest_nonce_h * >(hash_lookup(digest_nonce_cache, noncehex));

    if ((nonce == nullptr) || (strcmp(authenticateDigestNonceNonceHex(nonce), noncehex)))
        return nullptr;

    debugs(29, 9, "Found nonce '" << nonce << "'");

    return nonce;
}

int
authDigestNonceIsValid(digest_nonce_h * nonce, char nc[9])
{
    unsigned long intnc;
    /* do we have a nonce ? */

    if (!nonce)
        return 0;

    intnc = strtol(nc, nullptr, 16);

    /* has it already been invalidated ? */
    if (!nonce->flags.valid) {
        debugs(29, 4, "Nonce already invalidated");
        return 0;
    }

    /* is the nonce-count ok ? */
    if (!static_cast<Auth::Digest::Config*>(Auth::SchemeConfig::Find("digest"))->CheckNonceCount) {
        /* Ignore client supplied NC */
        intnc = nonce->nc + 1;
    }

    if ((static_cast<Auth::Digest::Config*>(Auth::SchemeConfig::Find("digest"))->NonceStrictness && intnc != nonce->nc + 1) ||
            intnc < nonce->nc + 1) {
        debugs(29, 4, "Nonce count doesn't match");
        nonce->flags.valid = false;
        return 0;
    }

    /* increment the nonce count - we've already checked that intnc is a
     *  valid representation for us, so we don't need the test here.
     */
    nonce->nc = intnc;

    return !authDigestNonceIsStale(nonce);
}

int
authDigestNonceIsStale(digest_nonce_h * nonce)
{
    /* do we have a nonce ? */

    if (!nonce)
        return -1;

    /* Is it already invalidated? */
    if (!nonce->flags.valid)
        return -1;

    /* has it's max duration expired? */
    if (nonce->noncedata.creationtime + static_cast<Auth::Digest::Config*>(Auth::SchemeConfig::Find("digest"))->noncemaxduration < current_time.tv_sec) {
        debugs(29, 4, "Nonce is too old. " <<
               nonce->noncedata.creationtime << " " <<
               static_cast<Auth::Digest::Config*>(Auth::SchemeConfig::Find("digest"))->noncemaxduration << " " <<
               current_time.tv_sec);

        nonce->flags.valid = false;
        return -1;
    }

    if (nonce->nc > 99999998) {
        debugs(29, 4, "Nonce count overflow");
        nonce->flags.valid = false;
        return -1;
    }

    if (nonce->nc > static_cast<Auth::Digest::Config*>(Auth::SchemeConfig::Find("digest"))->noncemaxuses) {
        debugs(29, 4, "Nonce count over user limit");
        nonce->flags.valid = false;
        return -1;
    }

    /* seems ok */
    return 0;
}

/**
 * \retval  0    the digest is not stale yet
 * \retval -1    the digest will be stale on the next request
 */
int
authDigestNonceLastRequest(digest_nonce_h * nonce)
{
    if (!nonce)
        return -1;

    if (nonce->nc == 99999997) {
        debugs(29, 4, "Nonce count about to overflow");
        return -1;
    }

    if (nonce->nc >= static_cast<Auth::Digest::Config*>(Auth::SchemeConfig::Find("digest"))->noncemaxuses - 1) {
        debugs(29, 4, "Nonce count about to hit user limit");
        return -1;
    }

    /* and other tests are possible. */
    return 0;
}

void
authDigestNoncePurge(digest_nonce_h * nonce)
{
    if (!nonce)
        return;

    if (!nonce->flags.incache)
        return;

    hash_remove_link(digest_nonce_cache, nonce);

    nonce->flags.incache = false;

    /* the cache's link */
    authDigestNonceUnlink(nonce);
}

void
Auth::Digest::Config::rotateHelpers()
{
    /* schedule closure of existing helpers */
    if (digestauthenticators) {
        helperShutdown(digestauthenticators);
    }

    /* NP: dynamic helper restart will ensure they start up again as needed. */
}

bool
Auth::Digest::Config::dump(StoreEntry * entry, const char *name, Auth::SchemeConfig * scheme) const
{
    if (!Auth::SchemeConfig::dump(entry, name, scheme))
        return false;

    storeAppendPrintf(entry, "%s %s nonce_max_count %d\n%s %s nonce_max_duration %d seconds\n%s %s nonce_garbage_interval %d seconds\n",
                      name, "digest", noncemaxuses,
                      name, "digest", (int) noncemaxduration,
                      name, "digest", (int) nonceGCInterval);
    return true;
}

bool
Auth::Digest::Config::active() const
{
    return authdigest_initialised == 1;
}

bool
Auth::Digest::Config::configured() const
{
    return (SchemeConfig::configured() && !realm.isEmpty() && noncemaxduration > -1);
}

/* add the [www-|Proxy-]authenticate header on a 407 or 401 reply */
void
Auth::Digest::Config::fixHeader(Auth::UserRequest::Pointer auth_user_request, HttpReply *rep, Http::HdrType hdrType, HttpRequest *)
{
    if (!authenticateProgram)
        return;

    bool stale = false;
    digest_nonce_h *nonce = nullptr;

    /* on a 407 or 401 we always use a new nonce */
    if (auth_user_request != nullptr) {
        Auth::Digest::User *digest_user = dynamic_cast<Auth::Digest::User *>(auth_user_request->user().getRaw());

        if (digest_user) {
            stale = digest_user->credentials() == Auth::Handshake;
            if (stale) {
                nonce = digest_user->currentNonce();
            }
        }
    }
    if (!nonce) {
        nonce = authenticateDigestNonceNew();
    }

    debugs(29, 9, "Sending type:" << hdrType <<
           " header: 'Digest realm=\"" << realm << "\", nonce=\"" <<
           authenticateDigestNonceNonceHex(nonce) << "\", qop=\"" << QOP_AUTH <<
           "\", stale=" << (stale ? "true" : "false"));

    /* in the future, for WWW auth we may want to support the domain entry */
    httpHeaderPutStrf(&rep->header, hdrType, "Digest realm=\"" SQUIDSBUFPH "\", nonce=\"%s\", qop=\"%s\", stale=%s",
                      SQUIDSBUFPRINT(realm), authenticateDigestNonceNonceHex(nonce), QOP_AUTH, stale ? "true" : "false");
}

/* Initialize helpers and the like for this auth scheme. Called AFTER parsing the
 * config file */
void
Auth::Digest::Config::init(Auth::SchemeConfig *)
{
    if (authenticateProgram) {
        authenticateDigestNonceSetup();
        authdigest_initialised = 1;

        if (digestauthenticators == nullptr)
            digestauthenticators = Helper::Client::Make("digestauthenticator");

        digestauthenticators->cmdline = authenticateProgram;

        digestauthenticators->childs.updateLimits(authenticateChildren);

        digestauthenticators->ipc_type = IPC_STREAM;

        digestauthenticators->openSessions();
    }
}

void
Auth::Digest::Config::registerWithCacheManager(void)
{
    Mgr::RegisterAction("digestauthenticator",
                        "Digest User Authenticator Stats",
                        authenticateDigestStats, 0, 1);
}

/* free any allocated configuration details */
void
Auth::Digest::Config::done()
{
    Auth::SchemeConfig::done();

    authdigest_initialised = 0;

    if (digestauthenticators)
        helperShutdown(digestauthenticators);

    if (!shutting_down)
        return;

    digestauthenticators = nullptr;

    if (authenticateProgram)
        wordlistDestroy(&authenticateProgram);
}

Auth::Digest::Config::Config() :
    nonceGCInterval(5*60),
    noncemaxduration(30*60),
    noncemaxuses(50),
    NonceStrictness(0),
    CheckNonceCount(1),
    PostWorkaround(0)
{}

void
Auth::Digest::Config::parse(Auth::SchemeConfig * scheme, size_t n_configured, char *param_str)
{
    if (strcmp(param_str, "nonce_garbage_interval") == 0) {
        parse_time_t(&nonceGCInterval);
    } else if (strcmp(param_str, "nonce_max_duration") == 0) {
        parse_time_t(&noncemaxduration);
    } else if (strcmp(param_str, "nonce_max_count") == 0) {
        parse_int((int *) &noncemaxuses);
    } else if (strcmp(param_str, "nonce_strictness") == 0) {
        parse_onoff(&NonceStrictness);
    } else if (strcmp(param_str, "check_nonce_count") == 0) {
        parse_onoff(&CheckNonceCount);
    } else if (strcmp(param_str, "post_workaround") == 0) {
        parse_onoff(&PostWorkaround);
    } else
        Auth::SchemeConfig::parse(scheme, n_configured, param_str);
}

const char *
Auth::Digest::Config::type() const
{
    return Auth::Digest::Scheme::GetInstance()->type();
}

static void
authenticateDigestStats(StoreEntry * sentry)
{
    if (digestauthenticators)
        digestauthenticators->packStatsInto(sentry, "Digest Authenticator Statistics");
}

/* NonceUserUnlink: remove the reference to auth_user and unlink the node from the list */

static void
authDigestNonceUserUnlink(digest_nonce_h * nonce)
{
    Auth::Digest::User *digest_user;
    dlink_node *link, *tmplink;

    if (!nonce)
        return;

    if (!nonce->user)
        return;

    digest_user = nonce->user;

    /* unlink from the user list. Yes we're crossing structures but this is the only
     * time this code is needed
     */
    link = digest_user->nonces.head;

    while (link) {
        tmplink = link;
        link = link->next;

        if (tmplink->data == nonce) {
            dlinkDelete(tmplink, &digest_user->nonces);
            authDigestNonceUnlink(static_cast < digest_nonce_h * >(tmplink->data));
            delete tmplink;
            link = nullptr;
        }
    }

    /* this reference to user was not locked because freeeing the user frees
     * the nonce too.
     */
    nonce->user = nullptr;
}

/* authDigesteserLinkNonce: add a nonce to a given user's struct */
void
authDigestUserLinkNonce(Auth::Digest::User * user, digest_nonce_h * nonce)
{
    dlink_node *node;

    if (!user || !nonce || !nonce->user)
        return;

    Auth::Digest::User *digest_user = user;

    node = digest_user->nonces.head;

    while (node && (node->data != nonce))
        node = node->next;

    if (node)
        return;

    node = new dlink_node;

    dlinkAddTail(nonce, node, &digest_user->nonces);

    authDigestNonceLink(nonce);

    /* ping this nonce to this auth user */
    assert((nonce->user == nullptr) || (nonce->user == user));

    /* we don't lock this reference because removing the user removes the
     * hash too. Of course if that changes we're stuffed so read the code huh?
     */
    nonce->user = user;
}

/* setup the necessary info to log the username */
static Auth::UserRequest::Pointer
authDigestLogUsername(char *username, Auth::UserRequest::Pointer auth_user_request, const char *requestRealm)
{
    assert(auth_user_request != nullptr);

    /* log the username */
    debugs(29, 9, "Creating new user for logging '" << (username?username:"[no username]") << "'");
    Auth::User::Pointer digest_user = new Auth::Digest::User(static_cast<Auth::Digest::Config*>(Auth::SchemeConfig::Find("digest")), requestRealm);
    /* save the credentials */
    digest_user->username(username);
    /* set the auth_user type */
    digest_user->auth_type = Auth::AUTH_BROKEN;
    /* link the request to the user */
    auth_user_request->user(digest_user);
    return auth_user_request;
}

/*
 * Decode a Digest [Proxy-]Auth string, placing the results in the passed
 * Auth_user structure.
 */
Auth::UserRequest::Pointer
Auth::Digest::Config::decode(char const *proxy_auth, const HttpRequest *request, const char *aRequestRealm)
{
    const char *item;
    const char *p;
    const char *pos = nullptr;
    char *username = nullptr;
    digest_nonce_h *nonce;
    int ilen;

    debugs(29, 9, "beginning");

    Auth::Digest::UserRequest *digest_request = new Auth::Digest::UserRequest();

    /* trim DIGEST from string */

    while (xisgraph(*proxy_auth))
        ++proxy_auth;

    /* Trim leading whitespace before decoding */
    while (xisspace(*proxy_auth))
        ++proxy_auth;

    String temp(proxy_auth);

    bool malformedFieldLength = false;

    /* Applies the DigestFieldCapacities[] contract to one credential field value
     * and records any rejection in malformedFieldLength, so that both the check
     * and its bookkeeping belong to the extraction loop rather than to nine
     * independently maintained cases. The parameters are those of
     * DigestFieldLengthOk(), named differently only to keep them distinct from
     * the per-attribute variables of the loop below.
     */
    const auto fieldLengthOk = [&malformedFieldLength](const http_digest_attr_type fieldType, const SBuf &fieldName, const String::size_type valueLength) {
        if (DigestFieldLengthOk(fieldType, fieldName, valueLength))
            return true;
        malformedFieldLength = true;
        return false;
    };

    while (strListGetItem(&temp, ',', &item, &ilen, &pos)) {
        /* isolate directive name & value */
        size_t nlen;
        size_t vlen;
        if ((p = (const char *)memchr(item, '=', ilen)) && (p - item < ilen)) {
            nlen = p - item;
            ++p;
            vlen = ilen - (p - item);
        } else {
            nlen = ilen;
            vlen = 0;
        }

        SBuf keyName(item, nlen);
        String value;

        if (vlen > 0) {
            // see RFC 2617 section 3.2.1 and 3.2.2 for details on the BNF

            if (keyName == SBuf("domain",6) || keyName == SBuf("uri",3)) {
                // domain is Special. Not a quoted-string, must not be de-quoted. But is wrapped in '"'
                // BUG 3077: uri= can also be sent to us in a mangled (invalid!) form like domain
                if (vlen > 1 && *p == '"' && *(p + vlen -1) == '"') {
                    value.assign(p+1, vlen-2);
                }
            } else if (keyName == SBuf("qop",3)) {
                // qop is more special.
                // On request this must not be quoted-string de-quoted. But is several values wrapped in '"'
                // On response this is a single un-quoted token.
                if (vlen > 1 && *p == '"' && *(p + vlen -1) == '"') {
                    value.assign(p+1, vlen-2);
                } else {
                    value.assign(p, vlen);
                }
            } else if (*p == '"') {
                if (!httpHeaderParseQuotedString(p, vlen, &value)) {
                    debugs(29, 9, "Failed to parse attribute '" << item << "' in '" << temp << "'");
                    continue;
                }
            } else {
                value.assign(p, vlen);
            }
        } else {
            debugs(29, 9, "Failed to parse attribute '" << item << "' in '" << temp << "'");
            continue;
        }

        /* find type */
        const auto t = digestFieldsLookupTable().lookup(keyName);

        /* unrecognized attributes are skipped here rather than by the switch
         * below: nothing is copied for them, so they have no destination whose
         * capacity could be checked, and checking them anyway would reject
         * credentials merely for carrying a long unknown attribute */
        if (t == DIGEST_INVALID_ATTR) {
            debugs(29, 3, "Unknown attribute '" << item << "' in '" << temp << "'");
            continue;
        }

        /* The check that guards every copy below. It runs on the value as it
         * arrived, before the username rewriting below, because no conversion
         * that rewriting performs can shrink a value: Latin1ToUtf8() expands a
         * high byte into two bytes and Cp1251ToUtf8() into up to three, and
         * neither ever emits fewer bytes than it read (src/auth/toUtf.cc). A
         * value already longer than its field admits is therefore still too long
         * once converted, so rejecting it here spares the conversion of a value
         * that could not have been stored either way.
         */
        if (!fieldLengthOk(t, keyName, value.size())) {
            /* nc is the one field whose destination has a fixed size, and it gets
             * two things the other eight do not. Its own diagnostic names the
             * offending value, which the length diagnostic above does not, since
             * that one reports the field and the length alone. Clearing the
             * destination keeps a wrong-length nc from leaving in place an nc that
             * an earlier item of the same credentials stored, which the rejection
             * below makes unusable but does not itself undo.
             */
            if (t == DIGEST_NC) {
                debugs(29, 9, "Invalid nc '" << value << "' in '" << temp << "'");
                digest_request->nc[0] = 0;
            }
            break;
        }

        /* The username is the only field this parser rewrites before copying it.
         * The length of the value it rewrites has been checked above; the length
         * of the value rewriting produces is checked again here, before that
         * value is stored, because the conversion can lengthen it and because a
         * String longer than String::SizeMax_ bytes asserts in
         * String::setBuffer() instead of failing cleanly.
         */
        if (t == DIGEST_USERNAME && value.size() != 0) {
            const auto v = value.termedBuf();
            if (utf8 && !isValidUtf8String(v, v + value.size())) {
                const auto str = isCP1251EncodingAllowed(request) ? Cp1251ToUtf8(v) : Latin1ToUtf8(v);
                if (!fieldLengthOk(t, keyName, str.length()))
                    break;
                value = SBufToString(str);
            }
        }

        /* The only place where a checked credential field value becomes a
         * heap-allocated C string. Routing every field through it keeps a case
         * below from copying a value that has not been through the check above,
         * and keeps the diagnostic inside the branch that made the field
         * non-nil, an empty value leaving it nil.
         */
        const auto storeField = [&value](char * &field, const char * const description) {
            safe_free(field);
            if (value.size() != 0) {
                field = xstrndup(value.rawBuf(), value.size() + 1);
                debugs(29, 9, "Found " << description << " '" << field << "'");
            }
        };

        switch (t) {
        case DIGEST_USERNAME:
            storeField(username, "Username");
            break;

        case DIGEST_REALM:
            storeField(digest_request->realm, "realm");
            break;

        case DIGEST_QOP:
            storeField(digest_request->qop, "qop");
            break;

        case DIGEST_ALGORITHM:
            storeField(digest_request->algorithm, "algorithm");
            break;

        case DIGEST_URI:
            storeField(digest_request->uri, "uri");
            break;

        case DIGEST_NONCE:
            storeField(digest_request->noncehex, "nonce");
            break;

        case DIGEST_NC:
            // for historical reasons, the nc value MUST be exactly 8 bytes
            static_assert(sizeof(digest_request->nc) == DigestFieldCapacities[DIGEST_NC].capacity + 1);
            xstrncpy(digest_request->nc, value.rawBuf(), value.size() + 1);
            debugs(29, 9, "Found noncecount '" << digest_request->nc << "'");
            break;

        case DIGEST_CNONCE:
            storeField(digest_request->cnonce, "cnonce");
            break;

        case DIGEST_RESPONSE:
            storeField(digest_request->response, "response");
            break;

        case DIGEST_INVALID_ATTR:
            /* unreachable: unrecognized attributes are skipped above. This case
             * exists so that the switch stays exhaustive without a default
             * label, making a new http_digest_attr_type that reaches a copy
             * without a case of its own a compilation error.
             */
            break;
        }
    }

    temp.clean();

    /* now we validate the data given to us */

    /*
     * TODO: on invalid parameters we should return 400, not 407.
     * Find some clean way of doing this. perhaps return a valid
     * struct, and set the direction to clientwards combined with
     * a change to the clientwards handling code (ie let the
     * clientwards call set the error type (but limited to known
     * correct values - 400/401/407
     */

    /* 2069 requirements */

    // return value.
    Auth::UserRequest::Pointer rv;

    /* Rejecting here, ahead of the checks below, keeps a rejected optional field
     * from being mistaken for an omitted one and quietly defaulted. The outcome
     * is the one every other rejection below produces: an Auth::Digest::User
     * marked Auth::AUTH_BROKEN, for which Auth::UserRequest::valid() is false,
     * so that Auth::UserRequest::authenticate() answers AUTH_ACL_CHALLENGE and
     * the client receives the standard 407 challenge on a forward-proxy port or
     * 401 on an accelerator port. The offending field and the length of its
     * value have already been reported above.
     */
    if (malformedFieldLength) {
        debugs(29, 2, "Disallowed credential field length");
        rv = authDigestLogUsername(username, digest_request, aRequestRealm);
        safe_free(username);
        return rv;
    }

    /* do we have a username ? */
    if (!username || username[0] == '\0') {
        debugs(29, 2, "Empty or not present username");
        rv = authDigestLogUsername(username, digest_request, aRequestRealm);
        safe_free(username);
        return rv;
    }

    /* Sanity check of the username.
     * " can not be allowed in usernames until * the digest helper protocol
     * have been redone
     */
    if (strchr(username, '"')) {
        debugs(29, 2, "Unacceptable username '" << username << "'");
        rv = authDigestLogUsername(username, digest_request, aRequestRealm);
        safe_free(username);
        return rv;
    }

    /* do we have a realm ? */
    if (!digest_request->realm || digest_request->realm[0] == '\0') {
        debugs(29, 2, "Empty or not present realm");
        rv = authDigestLogUsername(username, digest_request, aRequestRealm);
        safe_free(username);
        return rv;
    }

    /* and a nonce? */
    if (!digest_request->noncehex || digest_request->noncehex[0] == '\0') {
        debugs(29, 2, "Empty or not present nonce");
        rv = authDigestLogUsername(username, digest_request, aRequestRealm);
        safe_free(username);
        return rv;
    }

    /* we can't check the URI just yet. We'll check it in the
     * authenticate phase, but needs to be given */
    if (!digest_request->uri || digest_request->uri[0] == '\0') {
        debugs(29, 2, "Missing URI field");
        rv = authDigestLogUsername(username, digest_request, aRequestRealm);
        safe_free(username);
        return rv;
    }

    /* is the response the correct length? */
    if (!digest_request->response || strlen(digest_request->response) != 32) {
        debugs(29, 2, "Response length invalid");
        rv = authDigestLogUsername(username, digest_request, aRequestRealm);
        safe_free(username);
        return rv;
    }

    /* check the algorithm is present and supported */
    if (!digest_request->algorithm)
        digest_request->algorithm = xstrndup("MD5", 4);
    else if (strcmp(digest_request->algorithm, "MD5")
             && strcmp(digest_request->algorithm, "MD5-sess")) {
        debugs(29, 2, "invalid algorithm specified!");
        rv = authDigestLogUsername(username, digest_request, aRequestRealm);
        safe_free(username);
        return rv;
    }

    /* 2617 requirements, indicated by qop */
    if (digest_request->qop) {

        /* check the qop is what we expected. */
        if (strcmp(digest_request->qop, QOP_AUTH) != 0) {
            /* we received a qop option we didn't send */
            debugs(29, 2, "Invalid qop option received");
            rv = authDigestLogUsername(username, digest_request, aRequestRealm);
            safe_free(username);
            return rv;
        }

        /* check cnonce */
        if (!digest_request->cnonce || digest_request->cnonce[0] == '\0') {
            debugs(29, 2, "Missing cnonce field");
            rv = authDigestLogUsername(username, digest_request, aRequestRealm);
            safe_free(username);
            return rv;
        }

        /* check nc */
        if (strlen(digest_request->nc) != 8 || strspn(digest_request->nc, "0123456789abcdefABCDEF") != 8) {
            debugs(29, 2, "invalid nonce count");
            rv = authDigestLogUsername(username, digest_request, aRequestRealm);
            safe_free(username);
            return rv;
        }
    } else {
        /* RFC7616 section 3.3, qop:
         *  "MUST be used by all implementations"
         *
         * RFC7616 section 3.4, qop:
         *  "value MUST be one of the alternatives the server
         *   indicated it supports in the WWW-Authenticate header field"
         *
         * Squid sends qop=auth, reject buggy or outdated clients.
        */
        debugs(29, 2, "missing qop!");
        rv = authDigestLogUsername(username, digest_request, aRequestRealm);
        safe_free(username);
        return rv;
    }

    /** below nonce state dependent **/

    /* now the nonce */
    nonce = authenticateDigestNonceFindNonce(digest_request->noncehex);
    /* check that we're not being hacked / the username hasn't changed */
    if (nonce && nonce->user && strcmp(username, nonce->user->username())) {
        debugs(29, 2, "Username for the nonce does not equal the username for the request");
        nonce = nullptr;
    }

    if (!nonce) {
        /* we couldn't find a matching nonce! */
        debugs(29, 2, "Unexpected or invalid nonce received from " << username);
        Auth::UserRequest::Pointer auth_request = authDigestLogUsername(username, digest_request, aRequestRealm);
        auth_request->user()->credentials(Auth::Handshake);
        safe_free(username);
        return auth_request;
    }

    digest_request->nonce = nonce;
    authDigestNonceLink(nonce);

    /* check that we're not being hacked / the username hasn't changed */
    if (nonce->user && strcmp(username, nonce->user->username())) {
        debugs(29, 2, "Username for the nonce does not equal the username for the request");
        rv = authDigestLogUsername(username, digest_request, aRequestRealm);
        safe_free(username);
        return rv;
    }

    /* the method we'll check at the authenticate step as well */

    /* we don't send or parse opaques. Ok so we're flexible ... */

    /* find the user */
    Auth::Digest::User *digest_user;

    Auth::User::Pointer auth_user;

    SBuf key = Auth::User::BuildUserKey(username, aRequestRealm);
    if (key.isEmpty() || !(auth_user = Auth::Digest::User::Cache()->lookup(key))) {
        /* the user doesn't exist in the username cache yet */
        debugs(29, 9, "Creating new digest user '" << username << "'");
        digest_user = new Auth::Digest::User(this, aRequestRealm);
        /* auth_user is a parent */
        auth_user = digest_user;
        /* save the username */
        digest_user->username(username);
        /* set the user type */
        digest_user->auth_type = Auth::AUTH_DIGEST;
        /* this auth_user struct is the one to get added to the
         * username cache */
        /* store user in hash's */
        digest_user->addToNameCache();

        /*
         * Add the digest to the user so we can tell if a hacking
         * or spoofing attack is taking place. We do this by assuming
         * the user agent won't change user name without warning.
         */
        authDigestUserLinkNonce(digest_user, nonce);

        /* auth_user is now linked, we reset these values
         * after external auth occurs anyway */
        auth_user->expiretime = current_time.tv_sec;
    } else {
        debugs(29, 9, "Found user '" << username << "' in the user cache as '" << auth_user << "'");
        digest_user = static_cast<Auth::Digest::User *>(auth_user.getRaw());
        digest_user->credentials(Auth::Unchecked);
        xfree(username);
    }

    /*link the request and the user */
    assert(digest_request != nullptr);

    digest_request->user(digest_user);
    debugs(29, 9, "username = '" << digest_user->username() << "'\nrealm = '" <<
           digest_request->realm << "'\nqop = '" << digest_request->qop <<
           "'\nalgorithm = '" << digest_request->algorithm << "'\nuri = '" <<
           digest_request->uri << "'\nnonce = '" << digest_request->noncehex <<
           "'\nnc = '" << digest_request->nc << "'\ncnonce = '" <<
           digest_request->cnonce << "'\nresponse = '" <<
           digest_request->response << "'\ndigestnonce = '" << nonce << "'");

    return digest_request;
}

