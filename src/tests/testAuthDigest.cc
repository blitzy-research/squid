/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/cppunit.h"
#include "rfc2617.h"
#include "unitTestMain.h"

#include <string>

/* Unit coverage for the destination capacity contract that
 * Auth::Digest::Config::decode() applies to the fields of a Digest credential: a
 * table keyed by http_digest_attr_type and one shared predicate over it that every
 * field extraction consults before copying.
 *
 * That contract has internal linkage -- an anonymous namespace, no header, no
 * exported symbol -- because the authentication module interface is unchanged, so
 * this program mirrors it rather than calling it and asserts only what the mirror
 * declares: a change made to the production table alone fails nothing here.
 * Calling decode() instead would mean linking the real
 * httpHeaderParseQuotedString() and strListGetItem(); this program keeps the
 * minimal dependency set of tests/testLookupTable.
 *
 * The mirrored contract is the one decode() applies, that of the nine recognized
 * credential fields: two of them admit a single exact length and the other seven a
 * maximum. decode() resolves an unrecognized attribute to the DIGEST_INVALID_ATTR
 * lookup sentinel and skips it before reaching the check, so the sentinel carries
 * no capacity here and no assertion below names it.
 */

#if HAVE_AUTH_MODULE_DIGEST

namespace {

/// The Digest credential fields that Auth::Digest::Config::decode() extracts.
/// Mirrors the production http_digest_attr_type enumeration in membership and
/// order, since the capacity table below is indexed by it. The spellings follow
/// digestFieldsLookupTable() rather than the Auth::Digest::UserRequest member
/// names, which differ only for DIGEST_NONCE (member noncehex,
/// src/auth/digest/UserRequest.h:47).
///
/// DIGEST_INVALID_ATTR is not one of those fields but the value
/// digestFieldsLookupTable() yields for an attribute name it does not recognize,
/// which decode() skips before the length check, so no destination and no capacity
/// belong to it. It is retained because it terminates the enumeration, which makes
/// its value the number of recognized fields and the exclusive bound of every loop
/// below.
enum DigestFieldId {
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

/// the number of recognized fields, which the enumeration above states as the value
/// of its terminating enumerator
constexpr auto RecognizedFieldCount = static_cast<size_t>(DIGEST_INVALID_ATTR);

static_assert(RecognizedFieldCount == 9);

/// the credential attribute name of each recognized DigestFieldId, spelled as
/// digestFieldsLookupTable() spells it, so that a failed assertion names the field
/// it is about
constexpr const char *DigestFieldNames[] = {
    "username",
    "realm",
    "qop",
    "algorithm",
    "uri",
    "nonce",
    "nc",
    "cnonce",
    "response"
};

static_assert(sizeof(DigestFieldNames) / sizeof(DigestFieldNames[0]) == RecognizedFieldCount);

/// The upper bound that DigestFieldLengthOk() applies to every field before
/// applying that field's own rule, mirroring the String::RawSizeMaxXXX() bound the
/// production predicate applies first -- the conservative ceiling for raw input
/// that later processing may grow, a third of the String::SizeMaxXXX() absolute
/// limit (src/SquidString.h:74-76). A literal is unavoidable, both being static
/// member functions rather than constant expressions with String::SizeMax_ private
/// (src/SquidString.h:157), so the static_assert()s below restate their arithmetic.
constexpr size_t UniversalValueLengthBound = 65536;

static_assert(UniversalValueLengthBound == ((3 * 64 * 1024 - 1) + 1) / 3);
static_assert(UniversalValueLengthBound == 64 * 1024);

/// How DigestFieldCapacities[] constrains a field's value length. Mirrors the
/// production DigestLengthRule in order, and in membership for every rule a
/// recognized field uses. Production declares one further rule,
/// DigestLengthRule::any, which its table uses for the DIGEST_INVALID_ATTR row
/// alone. No recognized field carries it and decode() never submits the sentinel to
/// the check, so mirroring it here would add a rule no case could reach.
enum class DigestLengthRule {
    exact, ///< the capacity is the only length the field admits
    atMost, ///< the capacity is the greatest length the field admits
    /// the greatest length the field admits is the universal bound itself, which the
    /// row names instead of storing: String::RawSizeMaxXXX() is not constexpr
    rawSizeMax
};

constexpr bool
IsMaximumLengthRule(const DigestLengthRule rule)
{
    return rule == DigestLengthRule::atMost || rule == DigestLengthRule::rawSizeMax;
}

/// One row of the mirrored capacity contract. Mirrors the production
/// DigestFieldCapacity, whose String::size_type capacity src/SquidString.h:39
/// makes a size_t.
class DigestFieldCapacity
{
public:
    DigestFieldId id;
    DigestLengthRule rule;
    /// the value length in bytes that DigestLengthRule::exact and ::atMost compare
    /// against; DigestLengthRule::rawSizeMax names its limit and leaves this zero
    size_t capacity;
};

/// The mirrored length contract of every recognized Digest credential field,
/// indexed by DigestFieldId. Mirrors the nine recognized rows of the production
/// DigestFieldCapacities[] row for row, where each value's rationale is documented
/// in full; the rows below cite only what fixes each number. Production's tenth
/// row, for DIGEST_INVALID_ATTR, is not mirrored: see DigestFieldId above.
constexpr DigestFieldCapacity DigestFieldCapacities[] = {
    /* one of the two fields a client fills on the char buf[8192] helper request line
     * that startHelperLookup() (src/auth/digest/UserRequest.cc:274-297) composes */
    {DIGEST_USERNAME, DigestLengthRule::atMost, 1024},

    /* the other field on that same helper request line, so the same 1024 bytes.
     * Configuration does not impose this limit: the "realm" branch of
     * Auth::SchemeConfig::parse() accepts a realm of any length and the challenge
     * advertises whatever it accepted, so a realm configured longer than 1024 bytes
     * is issued but rejected here when a client echoes it */
    {DIGEST_REALM, DigestLengthRule::atMost, 1024},

    /* QOP_AUTH is the four bytes "auth" (src/auth/digest/Config.h:101) and the only
     * qop the validation after the parsing loop accepts; the headroom lets that
     * validation's own diagnostic report the 8-byte "auth-int" of RFC 7616 section
     * 3.4 */
    {DIGEST_QOP, DigestLengthRule::atMost, 8},

    /* "MD5" and "MD5-sess" are the only values that validation accepts, the longer
     * of them exactly 8 bytes */
    {DIGEST_ALGORITHM, DigestLengthRule::atMost, 8},

    /* request targets are legitimately long and nothing further down narrows this
     * one, so the row names the universal bound (src/SquidString.h:74-76) instead
     * of storing a limit */
    {DIGEST_URI, DigestLengthRule::rawSizeMax, 0},

    /* authDigestNonceEncode() issues nonces of exactly HASHHEXLEN bytes
     * (include/rfc2617.h:28-29) and authenticateDigestNonceFindNonce() matches a
     * received nonce against those alone, so no other length can match; 256 is
     * headroom */
    {DIGEST_NONCE, DigestLengthRule::atMost, 256},

    /* RFC 7616 section 3.4 makes the nonce-count 8 hexadecimal digits and the
     * destination is the char nc[9] of src/auth/digest/UserRequest.h:52, which the
     * DIGEST_NC case of decode() asserts against */
    {DIGEST_NC, DigestLengthRule::exact, 8},

    /* a client-chosen opaque value to which neither RFC 7616 section 3.4 nor
     * Auth::Digest::UserRequest::authenticate() gives a length, so 256 is a limit
     * this contract imposes: eightfold the HASHHEXLEN bytes
     * (include/rfc2617.h:28-29) of the nonce it accompanies */
    {DIGEST_CNONCE, DigestLengthRule::atMost, 256},

    /* include/rfc2617.h:28-29 fixes an MD5 hexadecimal digest at HASHHEXLEN bytes,
     * which the validation after the parsing loop also requires */
    {DIGEST_RESPONSE, DigestLengthRule::exact, HASHHEXLEN}
};

/**
 * Whether DigestFieldCapacities[] still describes the recognized DigestFieldId
 * values exactly. Mirrors the production DigestFieldCapacitiesAreWellFormed() and is
 * checked at compile time for the same reason: extending the enumeration without
 * declaring the new field's capacity must be a build failure. The one difference from
 * production is the row count, because production indexes its table by the whole
 * enumeration while this mirror holds only the fields the check is ever applied to.
 *
 \retval true  one row per recognized field, each at the index of the enumerator it
               describes and each carrying a capacity only if its rule reads one
 \retval false the table and the enumeration have drifted apart, or a row's rule
               and capacity disagree
 */
constexpr bool
DigestFieldCapacitiesAreWellFormed()
{
    if (sizeof(DigestFieldCapacities) / sizeof(DigestFieldCapacities[0]) != RecognizedFieldCount)
        return false;
    for (auto i = 0; i < DIGEST_INVALID_ATTR; ++i) {
        const auto &limit = DigestFieldCapacities[i];
        if (static_cast<int>(limit.id) != i)
            return false;
        /* a rule which compares against the stored capacity needs one; a rule which
         * names its limit instead must not store a second one nothing reads */
        const auto comparesAgainstCapacity = (limit.rule == DigestLengthRule::exact || limit.rule == DigestLengthRule::atMost);
        if (comparesAgainstCapacity != (limit.capacity > 0))
            return false;
    }
    return true;
}

static_assert(DigestFieldCapacitiesAreWellFormed());

constexpr size_t
FieldCountByRule(const DigestLengthRule rule)
{
    size_t found = 0;
    for (auto i = 0; i < DIGEST_INVALID_ATTR; ++i) {
        if (DigestFieldCapacities[i].rule == rule)
            ++found;
    }
    return found;
}

/// the nonce-count and the response, the two fields whose destination admits one
/// length and no other
constexpr auto ExactLengthFieldCount = FieldCountByRule(DigestLengthRule::exact);

/// the remaining seven, each declaring a greatest admitted length; six store that
/// length and the uri names the universal bound as its own
constexpr auto MaximumLengthFieldCount =
    FieldCountByRule(DigestLengthRule::atMost) + FieldCountByRule(DigestLengthRule::rawSizeMax);

static_assert(ExactLengthFieldCount == 2);
static_assert(MaximumLengthFieldCount == 7);
static_assert(ExactLengthFieldCount + MaximumLengthFieldCount == RecognizedFieldCount);

/* The compile-time capacity binding, mirrored. Production is authoritative: the
 * DIGEST_NC case of decode() asserts sizeof(digest_request->nc) against its row.
 * Reaching that char nc[9] (src/auth/digest/UserRequest.h:52) would mean including a
 * header this dependency-light program leaves out. */
static_assert(DigestFieldCapacities[DIGEST_NC].capacity == 8);
static_assert(DigestFieldCapacities[DIGEST_NC].capacity + 1 == 9);

/// the response row carries the RFC 2617 digest length itself (include/rfc2617.h:28)
static_assert(DigestFieldCapacities[DIGEST_RESPONSE].capacity == HASHHEXLEN);

/**
 * Whether a Digest credential field value of the given byte length may be copied
 * into the destination that Auth::Digest::Config::decode() keeps for that field.
 * Mirrors the production DigestFieldLengthOk(), including the order the two
 * constraints are applied in: the universal bound first, so that it also covers the
 * field whose only limit it is, then the field's own rule. The production predicate
 * also takes the field name and reports rejections through debugs(); this mirror
 * answers the length question alone.
 *
 * A length of 0 is admitted by every field except the two whose rule is a single
 * non-zero length, matching production, where an empty value is reachable and the
 * storing step then copies nothing. What follows a zero length is field-specific and
 * belongs to the validation after the parsing loop: a field that validation requires
 * is rejected as missing, while an absent or empty algorithm is defaulted to "MD5".
 *
 \param type[in]   the credential field being extracted; one of the nine recognized
                   fields, decode() having skipped an unrecognized attribute before
                   reaching the check
 \param length[in] the length in bytes of the value about to be copied; for
                   DIGEST_USERNAME production submits the length as it arrived and
                   again the length transcoding produced, which can be the greater
                   of the two
 \retval true  the destination admits a value of this length
 \retval false the length exceeds the universal bound, this field's stored capacity,
               or the single length a fixed-length field admits
 */
bool
DigestFieldLengthOk(const DigestFieldId type, const size_t length)
{
    auto fits = length <= UniversalValueLengthBound;

    if (fits) {
        // DigestFieldCapacitiesAreWellFormed() guarantees a row per recognized field
        const auto &limit = DigestFieldCapacities[type];
        switch (limit.rule) {
        case DigestLengthRule::exact:
            fits = (length == limit.capacity);
            break;
        case DigestLengthRule::atMost:
            fits = (length <= limit.capacity);
            break;
        case DigestLengthRule::rawSizeMax:
            fits = (length <= UniversalValueLengthBound);
            break;
        }
    }

    return fits;
}

/**
 * The longest value length the given field admits -- the greatest length
 * DigestFieldLengthOk() answers true for -- whatever the rule that establishes it,
 * so that the boundary assertions can treat all rows uniformly.
 *
 \param type[in] the recognized credential field to report the ceiling of
 \retval UniversalValueLengthBound  for DigestLengthRule::rawSizeMax, the rule that
         names its limit rather than storing one
 \retval DigestFieldCapacities[type].capacity  for the rules that compare against a
         stored capacity, DigestLengthRule::exact and DigestLengthRule::atMost
 */
constexpr size_t
EffectiveValueLengthLimit(const DigestFieldId type)
{
    const auto &limit = DigestFieldCapacities[type];
    const auto namesItsLimit = (limit.rule == DigestLengthRule::rawSizeMax);
    return namesItsLimit ? UniversalValueLengthBound : limit.capacity;
}

std::string
DescribeCase(const DigestFieldId type, const size_t length)
{
    return std::string("field ") + DigestFieldNames[type] +
           " at value length " + std::to_string(length) + " bytes";
}

void
AssertLengthAdmitted(const DigestFieldId type, const size_t length)
{
    CPPUNIT_ASSERT_MESSAGE("expected to admit " + DescribeCase(type, length),
                           DigestFieldLengthOk(type, length));
}

void
AssertLengthRejected(const DigestFieldId type, const size_t length)
{
    CPPUNIT_ASSERT_MESSAGE("expected to refuse " + DescribeCase(type, length),
                           !DigestFieldLengthOk(type, length));
}

void
AssertCapacityRow(const DigestFieldId type, const DigestLengthRule rule, const size_t capacity)
{
    const auto subject = std::string("capacity row of field ") + DigestFieldNames[type];
    CPPUNIT_ASSERT_EQUAL_MESSAGE(subject + " sits at its own index",
                                 static_cast<int>(type), static_cast<int>(DigestFieldCapacities[type].id));
    CPPUNIT_ASSERT_EQUAL_MESSAGE(subject + " rule",
                                 static_cast<int>(rule), static_cast<int>(DigestFieldCapacities[type].rule));
    CPPUNIT_ASSERT_EQUAL_MESSAGE(subject + " capacity",
                                 capacity, DigestFieldCapacities[type].capacity);
}

/// A syntactically well-formed Digest credential, the positive control of this
/// program: the length of every one of its field values must be admitted.
/// Reproduced as data from the canonical header of src/tests/testAuth.cc:54. It
/// carries no algorithm, which is well formed: decode() defaults an absent algorithm
/// to "MD5".
const char *const WellFormedCredentials =
    "Digest username=\"robertdig\", realm=\"Squid proxy-caching web server\", "
    "nonce=\"yy8rQXjEWwixXVBj\", uri=\"/images/bg8.gif\", "
    "response=\"f75a7d3edd48d93c681c75dc4fb58700\", qop=auth, nc=00000012, "
    "cnonce=\"e2216641961e228e\"";

class WellFormedField
{
public:
    DigestFieldId id;
    const char *value;
};

/// The field values of WellFormedCredentials. Their lengths are measured from these
/// spellings rather than transcribed, and every spelling is checked against the
/// credential itself, so neither can drift from the other.
constexpr WellFormedField WellFormedFields[] = {
    {DIGEST_USERNAME, "robertdig"},
    {DIGEST_REALM, "Squid proxy-caching web server"},
    {DIGEST_NONCE, "yy8rQXjEWwixXVBj"},
    {DIGEST_URI, "/images/bg8.gif"},
    {DIGEST_RESPONSE, "f75a7d3edd48d93c681c75dc4fb58700"},
    {DIGEST_QOP, "auth"},
    {DIGEST_NC, "00000012"},
    {DIGEST_CNONCE, "e2216641961e228e"}
};

} // namespace

class TestAuthDigest : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestAuthDigest);
    CPPUNIT_TEST(testCapacityTableMatchesParser);
    CPPUNIT_TEST(testExactLengthFields);
    CPPUNIT_TEST(testMaximumLengthFields);
    CPPUNIT_TEST(testMaximumIsTheRuntimeBound);
    CPPUNIT_TEST(testBoundaryTriples);
    CPPUNIT_TEST(testEmptyValues);
    CPPUNIT_TEST(testUniversalOuterBound);
    CPPUNIT_TEST(testWellFormedCredentialsAccepted);
    CPPUNIT_TEST_SUITE_END();

public:
    void testCapacityTableMatchesParser();
    void testExactLengthFields();
    void testMaximumLengthFields();
    void testMaximumIsTheRuntimeBound();
    void testBoundaryTriples();
    void testEmptyValues();
    void testUniversalOuterBound();
    void testWellFormedCredentialsAccepted();
};
CPPUNIT_TEST_SUITE_REGISTRATION(TestAuthDigest);

/* Every mirrored row stated in full, so that reading this method beside the
 * recognized rows of the production DigestFieldCapacities[] compares the two
 * tables. */
void
TestAuthDigest::testCapacityTableMatchesParser()
{
    CPPUNIT_ASSERT_MESSAGE("the mirrored table covers the recognized DigestFieldId values exactly",
                           DigestFieldCapacitiesAreWellFormed());
    CPPUNIT_ASSERT_EQUAL(size_t(9), RecognizedFieldCount);
    CPPUNIT_ASSERT_EQUAL(RecognizedFieldCount,
                         sizeof(DigestFieldCapacities) / sizeof(DigestFieldCapacities[0]));

    AssertCapacityRow(DIGEST_USERNAME, DigestLengthRule::atMost, 1024);
    AssertCapacityRow(DIGEST_REALM, DigestLengthRule::atMost, 1024);
    AssertCapacityRow(DIGEST_QOP, DigestLengthRule::atMost, 8);
    AssertCapacityRow(DIGEST_ALGORITHM, DigestLengthRule::atMost, 8);
    AssertCapacityRow(DIGEST_URI, DigestLengthRule::rawSizeMax, 0);
    AssertCapacityRow(DIGEST_NONCE, DigestLengthRule::atMost, 256);
    AssertCapacityRow(DIGEST_CNONCE, DigestLengthRule::atMost, 256);

    AssertCapacityRow(DIGEST_NC, DigestLengthRule::exact, 8);
    AssertCapacityRow(DIGEST_RESPONSE, DigestLengthRule::exact, HASHHEXLEN);

    /* the split the rows fall into, counted from the table rather than transcribed,
     * so that a rule changed above changes this outcome too */
    CPPUNIT_ASSERT_EQUAL(size_t(2), ExactLengthFieldCount);
    CPPUNIT_ASSERT_EQUAL(size_t(7), MaximumLengthFieldCount);
    CPPUNIT_ASSERT_EQUAL(RecognizedFieldCount, ExactLengthFieldCount + MaximumLengthFieldCount);

    CPPUNIT_ASSERT_EQUAL(size_t(65536), UniversalValueLengthBound);
    CPPUNIT_ASSERT_EQUAL(UniversalValueLengthBound, EffectiveValueLengthLimit(DIGEST_URI));
    /* the realm and the cnonce stated as the numbers themselves as well, these being
     * the two rows a length checked after the parsing loop never repeats, so that a
     * rule or a capacity changed above cannot leave them at the universal bound
     * unnoticed */
    CPPUNIT_ASSERT_EQUAL(size_t(1024), EffectiveValueLengthLimit(DIGEST_REALM));
    CPPUNIT_ASSERT_EQUAL(size_t(256), EffectiveValueLengthLimit(DIGEST_CNONCE));
    for (auto i = 0; i < DIGEST_INVALID_ATTR; ++i) {
        const auto type = static_cast<DigestFieldId>(i);
        if (type != DIGEST_URI) {
            CPPUNIT_ASSERT_MESSAGE(std::string("a ceiling of its own below the universal bound narrows ") + DigestFieldNames[type],
                                   EffectiveValueLengthLimit(type) < UniversalValueLengthBound);
        }
    }
}

/* DIGEST_NC and DIGEST_RESPONSE admit exactly one length each, so a value that is
 * too short is refused just as one that is too long is. The validation after the
 * parsing loop requires both lengths too. */
void
TestAuthDigest::testExactLengthFields()
{
    AssertLengthAdmitted(DIGEST_NC, 8);
    AssertLengthRejected(DIGEST_NC, 7);
    // the ninth byte of the destination is the terminator, not a ninth digit
    AssertLengthRejected(DIGEST_NC, 9);
    AssertLengthRejected(DIGEST_NC, 1);
    AssertLengthRejected(DIGEST_NC, 16);
    AssertLengthRejected(DIGEST_NC, 32000);
    AssertLengthRejected(DIGEST_NC, UniversalValueLengthBound);

    AssertLengthAdmitted(DIGEST_RESPONSE, HASHHEXLEN);
    AssertLengthRejected(DIGEST_RESPONSE, HASHHEXLEN - 1);
    AssertLengthRejected(DIGEST_RESPONSE, HASHHEXLEN + 1);
    AssertLengthRejected(DIGEST_RESPONSE, 16);
    AssertLengthRejected(DIGEST_RESPONSE, 64);
    AssertLengthRejected(DIGEST_RESPONSE, UniversalValueLengthBound);
}

/* The rows declaring a greatest admitted length rather than a single one. For the
 * three whose accepted values are enumerated or generated -- the qop, the algorithm
 * and the nonce -- that maximum sits at or above the longest value the validation
 * after the parsing loop accepts, leaving that validation's own diagnostics to
 * report the near misses. The username, the realm and the cnonce carry a stored
 * ceiling that no later length check repeats, so each is asserted at and one byte
 * past it -- the length past which an unauthenticated request can no longer enlarge
 * the copy. The uri names the universal bound rather than storing a number, so its
 * lengths are asserted in testMaximumIsTheRuntimeBound(). */
void
TestAuthDigest::testMaximumLengthFields()
{
    const DigestFieldId maximumLengthFields[] = {
        DIGEST_USERNAME, DIGEST_REALM, DIGEST_QOP, DIGEST_ALGORITHM, DIGEST_URI,
        DIGEST_NONCE, DIGEST_CNONCE
    };

    CPPUNIT_ASSERT_EQUAL(MaximumLengthFieldCount,
                         sizeof(maximumLengthFields) / sizeof(maximumLengthFields[0]));

    for (const auto type : maximumLengthFields) {
        CPPUNIT_ASSERT_MESSAGE(std::string("a greatest admitted length is what bounds ") + DigestFieldNames[type],
                               IsMaximumLengthRule(DigestFieldCapacities[type].rule));
    }

    AssertLengthAdmitted(DIGEST_USERNAME, 1);
    AssertLengthAdmitted(DIGEST_USERNAME, 32);
    AssertLengthAdmitted(DIGEST_USERNAME, 256);
    AssertLengthAdmitted(DIGEST_USERNAME, 1023);
    AssertLengthAdmitted(DIGEST_USERNAME, 1024);
    AssertLengthRejected(DIGEST_USERNAME, 1025);
    // a value the length of the whole helper request line
    AssertLengthRejected(DIGEST_USERNAME, 8192);
    AssertLengthRejected(DIGEST_USERNAME, UniversalValueLengthBound);

    AssertLengthAdmitted(DIGEST_REALM, 1);
    AssertLengthAdmitted(DIGEST_REALM, 30);
    AssertLengthAdmitted(DIGEST_REALM, 256);
    AssertLengthAdmitted(DIGEST_REALM, 1023);
    AssertLengthAdmitted(DIGEST_REALM, 1024);
    AssertLengthRejected(DIGEST_REALM, 1025);
    /* the shortest realm measured to overrun the helper request line, and with it the
     * newline framing that line, so that the helper waits for a line it never
     * receives */
    AssertLengthRejected(DIGEST_REALM, 8177);
    AssertLengthRejected(DIGEST_REALM, 8192);
    AssertLengthRejected(DIGEST_REALM, UniversalValueLengthBound);

    AssertLengthAdmitted(DIGEST_QOP, 4);
    AssertLengthAdmitted(DIGEST_QOP, 8);
    AssertLengthRejected(DIGEST_QOP, 9);
    AssertLengthRejected(DIGEST_QOP, 32);
    AssertLengthRejected(DIGEST_QOP, UniversalValueLengthBound);

    AssertLengthAdmitted(DIGEST_ALGORITHM, 3);
    AssertLengthAdmitted(DIGEST_ALGORITHM, 8);
    AssertLengthRejected(DIGEST_ALGORITHM, 9);
    AssertLengthRejected(DIGEST_ALGORITHM, 4096);
    AssertLengthRejected(DIGEST_ALGORITHM, UniversalValueLengthBound);

    AssertLengthAdmitted(DIGEST_NONCE, HASHHEXLEN);
    AssertLengthAdmitted(DIGEST_NONCE, 255);
    AssertLengthAdmitted(DIGEST_NONCE, 256);
    AssertLengthRejected(DIGEST_NONCE, 257);
    AssertLengthRejected(DIGEST_NONCE, 4096);
    AssertLengthRejected(DIGEST_NONCE, UniversalValueLengthBound);

    AssertLengthAdmitted(DIGEST_CNONCE, 8);
    AssertLengthAdmitted(DIGEST_CNONCE, 16);
    AssertLengthAdmitted(DIGEST_CNONCE, 64);
    AssertLengthAdmitted(DIGEST_CNONCE, 255);
    AssertLengthAdmitted(DIGEST_CNONCE, 256);
    AssertLengthRejected(DIGEST_CNONCE, 257);
    AssertLengthRejected(DIGEST_CNONCE, 1025);
    AssertLengthRejected(DIGEST_CNONCE, 4096);
    AssertLengthRejected(DIGEST_CNONCE, 8192);
    /* the lengths a client could once make this parser allocate before any credential
     * had been verified */
    AssertLengthRejected(DIGEST_CNONCE, 60000);
    AssertLengthRejected(DIGEST_CNONCE, UniversalValueLengthBound);
}

/* The one maximum-length field that no per-field number narrows: the uri, whose row
 * names the shared raw-input ceiling (DigestLengthRule::rawSizeMax) instead of
 * storing a limit, because String::RawSizeMaxXXX() is a runtime member function
 * rather than a constant expression, so the greatest length it admits is the
 * universal bound itself. The assertions well above 1024 bytes carry the weight
 * here, a request target being the one credential field a well-formed request can
 * legitimately make that long: refusing it for its length alone would refuse
 * credentials that authenticate. The bound asserted at the end is this predicate's
 * ceiling rather than a length a credential is expected to reach, since
 * HttpHeaderEntry::parse() (src/HttpHeader.cc:1619) refuses an Authorization field
 * value longer than 65534 bytes before these credentials are split into fields. The
 * field is asserted through a table-driven loop, rather than directly, so that a
 * second field given this rule has to be added to the array below before the count
 * assertion passes. */
void
TestAuthDigest::testMaximumIsTheRuntimeBound()
{
    const DigestFieldId unnarrowed[] = {DIGEST_URI};

    CPPUNIT_ASSERT_EQUAL(FieldCountByRule(DigestLengthRule::rawSizeMax),
                         sizeof(unnarrowed) / sizeof(unnarrowed[0]));

    for (const auto type : unnarrowed) {
        CPPUNIT_ASSERT_MESSAGE(std::string("the row of ") + DigestFieldNames[type] +
                               " names the shared raw-input ceiling rather than storing a limit",
                               DigestFieldCapacities[type].rule == DigestLengthRule::rawSizeMax);
        CPPUNIT_ASSERT_MESSAGE(std::string("naming that ceiling still makes a maximum-length field of ") + DigestFieldNames[type],
                               IsMaximumLengthRule(DigestFieldCapacities[type].rule));
        CPPUNIT_ASSERT_MESSAGE(std::string("no stored per-field limit on ") + DigestFieldNames[type],
                               DigestFieldCapacities[type].capacity == 0);
        CPPUNIT_ASSERT_EQUAL_MESSAGE(std::string("the universal bound is the only ceiling of ") + DigestFieldNames[type],
                                     UniversalValueLengthBound, EffectiveValueLengthLimit(type));

        AssertLengthAdmitted(type, 1);
        AssertLengthAdmitted(type, 32);
        AssertLengthAdmitted(type, 256);
        AssertLengthAdmitted(type, 257);
        AssertLengthAdmitted(type, 300);
        AssertLengthAdmitted(type, 1000);
        AssertLengthAdmitted(type, 1024);
        AssertLengthAdmitted(type, 1025);
        AssertLengthAdmitted(type, 8192);
        AssertLengthAdmitted(type, UniversalValueLengthBound - 1);
        AssertLengthAdmitted(type, UniversalValueLengthBound);

        AssertLengthRejected(type, UniversalValueLengthBound + 1);
    }
}

/* One length below, at, and above the ceiling of each recognized field. A field
 * admitting a single length is refused just below its ceiling; every other field is
 * admitted there. */
void
TestAuthDigest::testBoundaryTriples()
{
    for (auto i = 0; i < DIGEST_INVALID_ATTR; ++i) {
        const auto type = static_cast<DigestFieldId>(i);
        const auto ceiling = EffectiveValueLengthLimit(type);

        CPPUNIT_ASSERT_MESSAGE(std::string("a non-empty value fits ") + DigestFieldNames[type],
                               ceiling >= 1);

        if (DigestFieldCapacities[type].rule == DigestLengthRule::exact)
            AssertLengthRejected(type, ceiling - 1);
        else
            AssertLengthAdmitted(type, ceiling - 1);

        AssertLengthAdmitted(type, ceiling);
        AssertLengthRejected(type, ceiling + 1);
    }
}

/* An empty value is reachable: uri="" leaves the parsing loop with a zero-length
 * value. The contract admits one in every field except the two whose rule is a
 * single non-zero length, because the storing step then copies nothing. What follows
 * is field-specific and belongs to the validation after the parsing loop, which
 * rejects a field it requires as missing but defaults an absent or empty algorithm
 * to "MD5". */
void
TestAuthDigest::testEmptyValues()
{
    for (auto i = 0; i < DIGEST_INVALID_ATTR; ++i) {
        const auto type = static_cast<DigestFieldId>(i);
        if (DigestFieldCapacities[type].rule == DigestLengthRule::exact)
            AssertLengthRejected(type, 0);
        else
            AssertLengthAdmitted(type, 0);
    }
}

/* The universal bound applies to each recognized field, whatever its own rule says,
 * and it applies first, so a length above it is refused everywhere -- including
 * 196607, the String::SizeMax_ buffer size of src/SquidString.h:157 rather than a
 * length of content a String can usefully hold. */
void
TestAuthDigest::testUniversalOuterBound()
{
    for (auto i = 0; i < DIGEST_INVALID_ATTR; ++i) {
        const auto type = static_cast<DigestFieldId>(i);

        AssertLengthRejected(type, UniversalValueLengthBound + 1);
        AssertLengthRejected(type, 2 * UniversalValueLengthBound);

        AssertLengthRejected(type, 3 * 64 * 1024 - 1);
    }

    /* Each recognized field at the bound itself, so that every field states which
     * side of it it falls on: the uri is the one field whose own ceiling is the bound
     * and so the one field admitted there. */
    for (auto i = 0; i < DIGEST_INVALID_ATTR; ++i) {
        const auto type = static_cast<DigestFieldId>(i);
        if (EffectiveValueLengthLimit(type) < UniversalValueLengthBound)
            AssertLengthRejected(type, UniversalValueLengthBound);
        else
            AssertLengthAdmitted(type, UniversalValueLengthBound);
    }
}

/* The positive control: every field length of a syntactically well-formed
 * credential is admitted. Each value is located in WellFormedCredentials first, so
 * the lengths asserted are those of the credential quoted above. */
void
TestAuthDigest::testWellFormedCredentialsAccepted()
{
    const std::string credentials(WellFormedCredentials);

    for (const auto &field : WellFormedFields) {
        const std::string spelling(field.value);

        CPPUNIT_ASSERT_MESSAGE(std::string("the credentials carry the quoted ") + DigestFieldNames[field.id] + " value",
                               credentials.find(spelling) != std::string::npos);

        AssertLengthAdmitted(field.id, spelling.size());

        if (DigestFieldCapacities[field.id].rule == DigestLengthRule::exact) {
            CPPUNIT_ASSERT_EQUAL_MESSAGE(std::string("the credentials carry ") + DigestFieldNames[field.id] + " at its only admitted length",
                                         DigestFieldCapacities[field.id].capacity, spelling.size());
        }
    }

    /* the credential carries no algorithm, which is well formed: decode() defaults an
     * absent algorithm to "MD5" */
    CPPUNIT_ASSERT_MESSAGE("the credentials omit the optional algorithm",
                           credentials.find("algorithm") == std::string::npos);
    AssertLengthAdmitted(DIGEST_ALGORITHM, 3);
}

#endif /* HAVE_AUTH_MODULE_DIGEST */

int
main(int argc, char *argv[])
{
    return TestProgram().run(argc, argv);
}
