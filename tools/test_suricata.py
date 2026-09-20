#!/usr/bin/env python3
"""Tests for the Suricata translator.

The translator's governing rule is that a rule translated wrongly is worse
than one skipped, because it fails silently. That makes its behaviour on
awkward input the thing worth pinning down, and until now nothing did.

    python tools/test_suricata.py

Where a test needs ARGUS to agree that the output is loadable, it is run
through the real binary's `-check-rules`, built to a private directory for
the same reason `detect.py` does: a live capture may hold the ordinary one.
"""

import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import suricata as S  # noqa: E402

HOME = "192.168.0.0/16,10.0.0.0/8"


def rule(body, proto="http"):
    """Wraps rule options in a header, so tests read as the options."""
    return "alert %s any any -> any any (%s sid:1; rev:1;)" % (proto, body)


def convert(body, proto="http"):
    return S.convert(rule(body, proto), HOME)


class Pcre(unittest.TestCase):
    def test_a_plain_pcre_uses_byte_semantics(self):
        out, why = convert('http.uri; content:"/a"; pcre:"/a.b/";')
        self.assertIsNone(why)
        self.assertIn("(?-u)a.b", out, "PCRE runs on bytes; the crate's Unicode default would refuse a non-UTF-8 byte")

    def test_flags_are_kept_alongside_byte_semantics(self):
        out, _ = convert('http.uri; content:"/a"; pcre:"/abc/i";')
        self.assertIn("(?i-u)abc", out)

    def test_the_R_flag_resumes_from_the_previous_match(self):
        out, why = convert('http.uri; content:"/a"; pcre:"/b+/R";')
        self.assertIsNone(why)
        self.assertRegex(out, r'pcre:"[^"]*b\+"; relative')

    def test_a_leading_R_measures_from_the_start_of_the_buffer(self):
        # With no previous match, Suricata resumes from the start, which is
        # where an ordinary regex already looks.
        out, why = convert('http.uri; pcre:"/b+/R";')
        self.assertIsNone(why)
        self.assertNotIn("relative", out.split("pcre:")[1])

    def test_R_in_a_new_buffer_does_not_resume_from_the_last_one(self):
        out, why = convert('http.uri; content:"/a"; http.header; pcre:"/b+/R";')
        self.assertIsNone(why)
        header_part = out.split("buffer:http.header")[1]
        self.assertNotIn("relative", header_part)

    def test_a_buffer_flag_selects_the_buffer(self):
        out, why = convert('content:"x"; pcre:"/foo/U";', proto="tcp")
        self.assertIsNone(why)
        self.assertIn("buffer:http.uri", out)

    def test_conflicting_buffer_flags_are_refused(self):
        _, why = convert('http.uri; content:"/a"; pcre:"/foo/UH";')
        self.assertEqual(why, "pcre with several buffer flags")

    def test_an_unknown_flag_is_refused(self):
        _, why = convert('http.uri; content:"/a"; pcre:"/foo/A";')
        self.assertEqual(why, "pcre flag /A")

    def test_lookahead_selects_the_backtracking_engine(self):
        out, why = convert('http.uri; content:"foo"; pcre:"/foo(?!bar)/";')
        self.assertIsNone(why)
        self.assertIn('pcre_bt:"foo(?!bar)"', out)

    def test_the_bare_backtracking_engine_never_gets_byte_semantics_flag(self):
        # The text engine cannot switch Unicode off, so `-u` would not load.
        out, _ = convert('http.uri; content:"foo"; pcre:"/foo(?!bar)/";')
        self.assertNotIn("-u", out.split("pcre_bt:")[1])

    def test_a_backreference_is_detected(self):
        out, _ = convert('http.uri; content:"a"; pcre:"/(a+)b\\1/";')
        self.assertIn("pcre_bt:", out)

    def test_an_escaped_backslash_then_a_digit_is_not_a_backreference(self):
        # `\\1` is a literal backslash followed by the digit one, which
        # the regex this replaced took for a backreference and skipped.
        needs, hard = S.scan_pcre("a\\\\1b")
        self.assertFalse(needs)
        self.assertIsNone(hard)

    def test_a_lookahead_inside_a_character_class_is_not_a_lookahead(self):
        needs, _ = S.scan_pcre("[(?=]x")
        self.assertFalse(needs)

    def test_possessive_and_atomic_are_detected(self):
        self.assertIn("possessive quantifier", S.scan_pcre("a++b")[0])
        self.assertIn("atomic group", S.scan_pcre("(?>ab)c")[0])

    def test_a_recursive_pattern_is_refused(self):
        _, hard = S.scan_pcre("(?R)")
        self.assertTrue(hard)

    def test_shorthand_classes_are_made_ascii_for_the_text_engine(self):
        wide = S.widen_pattern(r"\w+\d\s", False)
        self.assertEqual(wide, "[A-Za-z0-9_]+[0-9][ \\t\\n\\r\\f\\v]")

    def test_a_negated_shorthand_inside_a_class_is_refused(self):
        self.assertIsNone(S.widen_pattern(r"[\W]x", False))

    def test_case_folding_high_bytes_is_refused_for_the_text_engine(self):
        # Unicode folding would reach Latin-1 letters PCRE leaves alone.
        self.assertIsNone(S.widen_pattern(r"\xe9", True))
        self.assertIsNotNone(S.widen_pattern(r"\xe9", False))

    def test_a_backtracking_pcre_on_the_raw_stream_needs_a_literal(self):
        # The raw stream is scanned for every packet, so a step-limited
        # regex with nothing to prefilter it would run against all of them.
        _, why = convert('pcre:"/foo(?!bar)/";', proto="tcp")
        self.assertEqual(why, "backtracking pcre with no literal to prefilter on")

    def test_a_backtracking_pcre_on_a_per_request_buffer_is_accepted(self):
        out, why = convert('http.uri; pcre:"/foo(?!bar)/";')
        self.assertIsNone(why)
        self.assertIn("pcre_bt", out)

    def test_a_bare_NUL_escape_is_spelled_out(self):
        out, _ = convert('http.uri; content:"a"; pcre:"/a\\0b/";')
        self.assertIn("a\\x00b", out)

    def test_an_escaped_backslash_before_a_zero_is_left_alone(self):
        out, _ = convert('http.uri; content:"a"; pcre:"/a\\\\0b/";')
        self.assertIn("a\\\\0b", out)

    def test_a_bare_bracket_inside_a_class_is_escaped(self):
        # PCRE reads `[sS[eE]` as one class; Rust reads a nested class.
        self.assertEqual(S.normalise_regex("[sS[eE]"), "[sS\\[eE]")

    def test_posix_classes_are_left_alone(self):
        self.assertEqual(S.normalise_regex("[[:alpha:]x]"), "[[:alpha:]x]")

    def test_a_one_digit_hex_escape_is_padded(self):
        self.assertEqual(S.normalise_regex(r"[\x2\x60]"), r"[\x02\x60]")

    def test_a_literal_brace_is_escaped_but_a_quantifier_is_not(self):
        self.assertEqual(S.escape_literal_braces("a{2}b{c"), "a{2}b\\{c")


class Buffers(unittest.TestCase):
    def test_header_names_and_request_line_translate(self):
        out, why = convert('http.header_names; content:"|0d 0a|Host|0d 0a|";')
        self.assertIsNone(why)
        self.assertIn("buffer:http.header_names", out)
        out, why = convert('http.request_line; content:"GET /";')
        self.assertIsNone(why)
        self.assertIn("buffer:http.request_line", out)

    def test_several_buffers_become_several_buffer_options(self):
        out, why = convert('http.uri; content:"/a"; http.header; content:"b";')
        self.assertIsNone(why)
        self.assertLess(out.index("buffer:http.uri"), out.index("buffer:http.header"))

    def test_a_negation_only_part_on_a_structured_buffer_is_accepted(self):
        # "The user agent is not Mozilla" is a claim about a complete,
        # per-message buffer. This used to be refused as a blanket footgun
        # guard, which turned out to exclude about 1,600 legitimate rules.
        out, why = convert('http.uri; content:"/a"; http.user_agent; content:!"Mozilla";')
        self.assertIsNone(why)
        self.assertIn('!content:"Mozilla"', out)

    def test_a_leading_distance_and_within_become_a_window_from_the_start(self):
        # Nothing precedes it in its buffer, so Suricata measures from zero:
        # `distance:D; within:W` is a match starting at or after D and
        # ending within W bytes of that.
        out, why = convert('http.uri; content:"/a"; http.header; content:"b"; distance:3; within:10;')
        self.assertIsNone(why)
        header_part = out.split("buffer:http.header")[1]
        self.assertIn("offset:3", header_part)
        self.assertIn("depth:7", header_part)
        self.assertNotIn("distance", header_part)
        self.assertNotIn("within", header_part)

    def test_a_relative_modifier_after_a_match_in_the_same_buffer_is_kept(self):
        out, why = convert('http.uri; content:"/a"; content:"b"; distance:1; within:5;')
        self.assertIsNone(why)
        self.assertIn("distance:1", out)
        self.assertIn("within:5", out)


class CaseTransforms(unittest.TestCase):
    """`to_lowercase` folds the whole buffer, so a lowercase content matches
    it case-insensitively — and an uppercase one can never match at all."""

    def test_to_lowercase_makes_a_content_case_insensitive(self):
        out, why = convert('http.uri; to_lowercase; content:"/admin";')
        self.assertIsNone(why)
        self.assertIn("nocase", out)

    def test_an_uppercase_content_could_never_match_so_the_rule_is_refused(self):
        # Emitting it with `nocase` would make a rule that never fires
        # start firing, which is a change of meaning, not a translation.
        _, why = convert('http.uri; to_lowercase; content:"/Admin";')
        self.assertEqual(why, "content can never match under to_lowercase")

    def test_to_uppercase_is_the_mirror_image(self):
        out, why = convert('http.uri; to_uppercase; content:"/ADMIN";')
        self.assertIsNone(why)
        self.assertIn("nocase", out)
        _, why = convert('http.uri; to_uppercase; content:"/admin";')
        self.assertEqual(why, "content can never match under to_uppercase")

    def test_a_transform_applies_to_its_own_buffer_only(self):
        out, why = convert('http.uri; to_lowercase; content:"/a"; http.header; content:"B";')
        self.assertIsNone(why)
        after_header = out.split("buffer:http.header")[1]
        self.assertNotIn("nocase", after_header, "the header buffer was never folded")

    def test_a_transform_written_after_a_content_still_covers_it(self):
        # Suricata folds the buffer, not "what follows", so position within
        # the sticky buffer does not matter.
        out, why = convert('http.uri; content:"/a"; to_lowercase;')
        self.assertIsNone(why)
        self.assertIn("nocase", out)

    def test_a_pcre_under_a_transform_becomes_case_insensitive(self):
        out, why = convert('http.uri; to_lowercase; content:"/a"; pcre:"/a[0-9]+/";')
        self.assertIsNone(why)
        self.assertIn("(?i-u)", out)

    def test_a_pcre_naming_an_uppercase_letter_is_refused(self):
        _, why = convert('http.uri; to_lowercase; content:"/a"; pcre:"/[A-Z]+/";')
        self.assertEqual(why, "pcre names a letter its case transform removes")
        _, why = convert('http.uri; to_lowercase; content:"/a"; pcre:"/a\\x41/";')
        self.assertEqual(why, "pcre names a letter its case transform removes")

    def test_escape_classes_are_not_mistaken_for_letters(self):
        # `\W` and `\D` are escapes, not the capital letters W and D.
        _, why = convert('http.uri; to_lowercase; content:"/a"; pcre:"/\\W+\\D/";')
        self.assertIsNone(why)

    def test_conflicting_transforms_are_refused(self):
        _, why = convert('http.uri; to_lowercase; to_uppercase; content:"/a";')
        self.assertEqual(why, "conflicting case transforms")

    def test_header_lowercase_is_a_transform_not_a_case_fold(self):
        # It folds header *names* only, so it must not become `nocase`
        # (which would also fold values): it is passed to ARGUS as a
        # transform of the buffer.
        out, why = convert('http.header; header_lowercase; content:"host|3a 20|x";')
        self.assertIsNone(why)
        self.assertIn("transform:header_lowercase", out)
        self.assertNotIn("nocase", out)


class NegationOnlyParts(unittest.TestCase):
    def test_absence_of_a_header_translates(self):
        out, why = convert('http.uri; content:"/gate.php"; http.header_names; content:!"|0d 0a|Accept|0d 0a|";')
        self.assertIsNone(why)
        self.assertIn('!content:"|0d 0a|Accept|0d 0a|"', out)

    def test_a_negation_only_part_on_the_raw_payload_is_refused(self):
        _, why = convert('content:!"x"; http.uri; content:"/a";')
        self.assertEqual(why, "payload part with only negated terms")

    def test_a_rule_that_is_all_negations_is_still_refused(self):
        _, why = convert('http.uri; content:!"a"; http.header; content:!"b";')
        self.assertIsNotNone(why)


class LengthTests(unittest.TestCase):
    """urilen, bsize, dsize and isdataat."""

    def test_urilen_becomes_a_length_test_on_the_uri(self):
        out, why = convert('http.uri; content:"/a"; urilen:12;')
        self.assertIsNone(why)
        self.assertIn("bsize:12", out.split("buffer:http.uri")[1])

    def test_every_urilen_form_is_kept_verbatim(self):
        for form in ("12", "<5", ">5", "3<>10"):
            out, why = convert('http.uri; content:"/a"; urilen:%s;' % form)
            self.assertIsNone(why, form)
            self.assertIn("bsize:%s" % form, out)

    def test_a_range_is_passed_through_not_widened(self):
        # `A<>B` is exclusive at both ends in Suricata and in ARGUS; turning
        # it into `>=A,<=B` would match two lengths the rule does not mean.
        out, _ = convert('http.uri; content:"/a"; urilen:3<>10;')
        self.assertIn("bsize:3<>10", out)

    def test_a_urilen_modifier_is_refused(self):
        # `,norm` and `,raw` select a different form of the URI.
        _, why = convert('http.uri; content:"/a"; urilen:12,norm;')
        self.assertEqual(why, "'urilen' form")

    def test_urilen_written_first_still_lands_in_the_uri_part(self):
        out, why = convert('urilen:12; http.method; content:"POST"; http.uri; content:"/x";')
        self.assertIsNone(why)
        self.assertEqual(out.count("buffer:http.uri"), 1, "one URI part, not two")
        self.assertGreater(out.index("bsize:12"), out.index("buffer:http.uri"))

    def test_urilen_with_no_uri_content_adds_a_length_only_uri_part(self):
        out, why = convert('urilen:12; http.method; content:"POST";')
        self.assertIsNone(why)
        self.assertIn("buffer:http.uri; transform:percent_decode; bsize:12", out)

    def test_bsize_no_longer_needs_the_content_to_span_the_buffer(self):
        # This used to be refused ("bsize with partial content"): the old
        # translation only worked when the content *was* the whole buffer.
        out, why = convert('http.host; bsize:10; content:"a";')
        self.assertIsNone(why)
        self.assertIn("bsize:10", out)

    def test_bsize_accepts_a_range(self):
        out, why = convert('http.host; bsize:5<>20; content:"a";')
        self.assertIsNone(why)
        self.assertIn("bsize:5<>20", out)

    def test_dsize_is_a_header_option_on_a_raw_payload_rule(self):
        out, why = convert('dsize:>100; content:"x";', proto="udp")
        self.assertIsNone(why)
        self.assertIn("dsize:>100", out)
        self.assertLess(out.index("dsize:>100"), out.index("buffer:"))

    def test_dsize_with_a_parsed_buffer_is_refused(self):
        # A request may span several packets, so there is no single packet
        # the rule's author could have meant.
        _, why = convert('dsize:>100; http.uri; content:"/a";')
        self.assertEqual(why, "dsize with a structured buffer")

    def test_isdataat_is_written_through(self):
        out, why = convert('content:"a"; isdataat:!4,relative;', proto="tcp")
        self.assertIsNone(why)
        self.assertIn("isdataat:!4,relative", out)

    def test_isdataat_spacing_is_normalised(self):
        out, _ = convert('content:"a"; isdataat:!4, relative;', proto="tcp")
        self.assertIn("isdataat:!4,relative", out)

    def test_an_absolute_isdataat_translates(self):
        out, why = convert('content:"a"; isdataat:50;', proto="tcp")
        self.assertIsNone(why)
        self.assertIn("isdataat:50", out)

    def test_a_variable_in_isdataat_is_refused(self):
        _, why = convert('content:"a"; isdataat:!length,relative;', proto="tcp")
        self.assertEqual(why, "isdataat form")

    def test_a_length_test_alone_is_not_a_rule(self):
        # Nothing says what to look for, so it would match every request of
        # that length.
        _, why = convert("http.uri; bsize:>5;")
        self.assertIsNotNone(why)


class AnchoredWindows(unittest.TestCase):
    """`endswith` combined with `offset`/`depth`."""

    def matcher(self, mods):
        import re
        out, why = convert('http.uri; content:"abc"; %s endswith;' % mods)
        self.assertIsNone(why)
        pat = out.split('pcre:"(?-u)', 1)[1].split('"', 1)[0]
        return re.compile(pat.encode())

    def test_offset_bounds_the_bytes_before_the_content(self):
        m = self.matcher("offset:2;")
        self.assertTrue(m.search(b"xxabc"))
        self.assertTrue(m.search(b"xxxxxabc"))
        self.assertFalse(m.search(b"xabc"), "starts before the offset")
        self.assertFalse(m.search(b"xxabcx"), "does not end the buffer")

    def test_depth_bounds_where_the_content_must_end(self):
        # depth counts from the offset and must cover the whole content.
        m = self.matcher("offset:2; depth:6;")
        self.assertTrue(m.search(b"xxabc"))
        self.assertTrue(m.search(b"xxxxxabc"), "starts at 5, ends at 8: the last byte in the window")
        self.assertFalse(m.search(b"xxxxxxabc"), "ends at 9, past offset+depth")
        self.assertFalse(m.search(b"xabc"))

    def test_a_window_too_small_for_the_content_is_refused(self):
        _, why = convert('http.uri; content:"abc"; depth:2; endswith;')
        self.assertEqual(why, "anchored content with offset/depth")

    def test_a_relative_modifier_is_still_refused(self):
        _, why = convert('http.uri; content:"x"; content:"abc"; distance:1; offset:2; endswith;')
        self.assertEqual(why, "anchored content with offset/depth")


class RateControl(unittest.TestCase):
    def test_threshold_is_passed_through_normalised(self):
        out, why = convert('content:"abc"; threshold:type limit, track by_src, count 1, seconds 60;', proto="tcp")
        self.assertIsNone(why)
        self.assertIn("threshold:type limit,track by_src,count 1,seconds 60", out)

    def test_detection_filter_needs_no_type(self):
        out, why = convert('content:"abc"; detection_filter:track by_dst, count 30, seconds 5;', proto="tcp")
        self.assertIsNone(why)
        self.assertIn("detection_filter:track by_dst,count 30,seconds 5", out)

    def test_tracking_by_flow_is_refused(self):
        _, why = convert('content:"abc"; threshold:type limit, track by_flow, count 1, seconds 60;', proto="tcp")
        self.assertEqual(why, "'threshold' form")

    def test_a_threshold_missing_a_field_is_refused(self):
        _, why = convert('content:"abc"; threshold:type limit, track by_src, count 1;', proto="tcp")
        self.assertEqual(why, "'threshold' form")

    def test_a_repeated_field_is_refused(self):
        _, why = convert('content:"abc"; detection_filter:track by_src, track by_dst, count 1, seconds 5;', proto="tcp")
        self.assertEqual(why, "'detection_filter' form")


class ByteOps(unittest.TestCase):
    def test_every_operator_form_is_accepted(self):
        for v in ("1,&,128,6,relative", "1,!&,128,0", "2,>,81,2,relative", "4,<=,400,0", "0,=,0,0,string,dec", "1,&,0x80,6,relative", "2,>,3,4,little"):
            self.assertEqual(S.normalise_byte_op(v), v, v)

    def test_a_named_variable_is_refused_in_any_slot(self):
        for v in ("1,>,kelihos.p,0", "1,>,len,0", "off,>,3,0"):
            self.assertIsNone(S.normalise_byte_op(v), v)

    def test_byte_jump_takes_two_numbers_then_modifiers(self):
        self.assertEqual(S.normalise_byte_op("2,-4,relative", 2), "2,-4,relative")
        self.assertIsNone(S.normalise_byte_op("2,off,relative", 2))

    def test_a_byte_test_rule_with_an_operator_translates(self):
        out, why = convert('content:"a"; byte_test:1,&,128,6,relative;', proto="tcp")
        self.assertIsNone(why)
        self.assertIn("byte_test:1,&,128,6,relative", out)


class RelativeWindows(unittest.TestCase):
    def test_a_negative_distance_is_kept(self):
        out, why = convert('http.uri; content:"a"; content:"b"; distance:-3;')
        self.assertIsNone(why)
        self.assertIn("distance:-3", out)

    def test_a_negative_within_is_refused(self):
        _, why = convert('http.uri; content:"a"; content:"b"; within:-3;')
        self.assertIsNotNone(why)

    def test_a_variable_distance_is_still_refused(self):
        _, why = convert('http.uri; content:"a"; content:"b"; distance:len;')
        self.assertEqual(why, "'distance' is not a constant")

    def test_a_leading_window_is_from_offset_to_within(self):
        # Measured from the start of the buffer, the window is [D, W]; the
        # depth ARGUS wants is counted from the offset, so W - D.
        out, why = convert('http.uri; content:"/a"; http.header; content:"b"; distance:3; within:10;')
        self.assertIsNone(why)
        part = out.split("buffer:http.header")[1]
        self.assertIn("offset:3", part)
        self.assertIn("depth:7", part)


class PacketLevel(unittest.TestCase):
    def test_tcp_pkt_reads_the_packet_not_the_stream(self):
        out, why = convert('content:"abc";', proto="tcp-pkt")
        self.assertIsNone(why)
        self.assertIn("buffer:packet", out)
        self.assertIn("proto:tcp", out)

    def test_a_header_only_rule_is_about_the_packet(self):
        out, why = convert("flags:S; itype:8;", proto="tcp")
        self.assertIsNone(why)
        self.assertIn("flags:S", out)
        self.assertIn("buffer:packet", out)

    def test_every_flag_form_passes_through(self):
        for spec in ("S", "SA", "S,12", "+SA", "*SA", "!S"):
            out, why = convert('flags:%s; content:"x";' % spec, proto="tcp")
            self.assertIsNone(why, spec)
            self.assertIn("flags:%s" % spec, out)

    def test_an_unknown_flag_form_is_refused(self):
        _, why = convert('flags:S+; content:"x";', proto="tcp")
        self.assertEqual(why, "'flags' form")

    def test_stream_size_is_kept(self):
        out, why = convert('stream_size:server,>,100; content:"x";', proto="tcp")
        self.assertIsNone(why)
        self.assertIn("stream_size:server,>,100", out)

    def test_icmp_type_and_code(self):
        out, why = convert('itype:8; icode:0; content:"x";', proto="icmp")
        self.assertIsNone(why)
        self.assertIn("itype:8", out)
        self.assertIn("icode:0", out)

    def test_dsize_may_sit_with_a_packet_rule(self):
        out, why = convert('dsize:>10; content:"x";', proto="tcp-pkt")
        self.assertIsNone(why)
        self.assertIn("dsize:>10", out)


class TwoLineRules(unittest.TestCase):
    def rule(self, header, body):
        return 'alert %s (msg:"t"; %s sid:1; rev:1;)' % (header, body)

    def test_a_bidirectional_rule_is_written_both_ways_round(self):
        out, why = S.convert(self.rule("tcp 10.0.0.1 80 <> 10.0.0.2 any", 'content:"abc";'), "")
        self.assertIsNone(why)
        lines = out.splitlines()
        self.assertEqual(len(lines), 2)
        self.assertIn("src_ip:10.0.0.1", lines[0])
        self.assertIn("src_ip:10.0.0.2", lines[1])
        self.assertIn("src_port:80", lines[0])
        self.assertIn("dst_port:80", lines[1])

    def test_a_bidirectional_rule_that_names_a_side_is_refused(self):
        _, why = S.convert(self.rule("tcp any any <> any any", 'flow:to_server; content:"abc";'), "")
        self.assertEqual(why, "bidirectional rule")

    def test_a_dns_rule_with_no_direction_is_scoped_at_either_end(self):
        out, why = S.convert(self.rule("dns any any -> any any", 'content:"|01 00|";'), "")
        self.assertIsNone(why)
        lines = out.splitlines()
        self.assertEqual(len(lines), 2)
        self.assertTrue(any("dst_port:53" in l for l in lines))
        self.assertTrue(any("src_port:53" in l for l in lines))

    def test_a_dns_rule_already_naming_the_port_is_left_alone(self):
        out, why = S.convert(self.rule("dns any any -> any 53", 'flow:to_server; content:"|01 00|";'), "")
        self.assertIsNone(why)
        self.assertEqual(len(out.splitlines()), 1)


class Transforms(unittest.TestCase):
    def test_url_decode_becomes_a_transform_on_the_raw_uri(self):
        out, why = convert('http.uri.raw; url_decode; content:"../";')
        self.assertIsNone(why)
        part = out.split("buffer:http.uri")[1]
        self.assertIn("transform:url_decode", part)
        # The raw URI is read as sent, so it is not also percent-decoded.
        self.assertNotIn("percent_decode", part)

    def test_the_normalised_uri_is_percent_decoded(self):
        out, why = convert('http.uri; content:"/a";')
        self.assertIsNone(why)
        self.assertIn("transform:percent_decode", out)

    def test_the_raw_uri_is_not_transformed(self):
        out, why = convert('http.uri.raw; content:"/a";')
        self.assertIsNone(why)
        self.assertNotIn("transform:", out)

    def test_pseudo_header_stripping_is_a_no_op_on_http1(self):
        out, why = convert('http.header_names; strip_pseudo_headers; content:"|0d 0a|Host|0d 0a|";')
        self.assertIsNone(why)
        self.assertNotIn("strip_pseudo", out)

    def test_whitespace_transforms_translate(self):
        for kw in ("strip_whitespace", "compress_whitespace"):
            out, why = convert('http.response_body; %s; content:"abc";' % kw)
            self.assertIsNone(why, kw)
            self.assertIn("transform:%s" % kw, out)

    def test_a_transform_stays_with_its_own_buffer(self):
        out, _ = convert('http.uri.raw; url_decode; content:"a"; http.header; content:"b";')
        header_part = out.split("buffer:http.header")[1]
        self.assertNotIn("transform:", header_part)


class AppIdentity(unittest.TestCase):
    def test_a_payload_rule_of_an_app_type_is_scoped_to_the_identified_protocol(self):
        out, why = convert('flow:established,to_server; content:"|03 00|";', proto="rdp")
        self.assertIsNone(why)
        self.assertIn("flowbits:isset,app.rdp", out)

    def test_http_and_tls_rules_use_their_own_identity(self):
        for proto in ("smtp", "ftp", "ssh", "smb", "tls"):
            out, why = convert('flow:established,to_server; content:"abc";', proto=proto)
            self.assertIsNone(why, proto)
            self.assertIn("flowbits:isset,app.%s" % proto, out)

    def test_dns_is_scoped_by_port(self):
        out, why = convert('flow:to_server; content:"|01 00|";', proto="dns")
        self.assertIsNone(why)
        self.assertIn("dst_port:53", out)

    def test_a_structured_buffer_needs_no_identity_bit(self):
        out, why = convert('flow:established,to_server; http.uri; content:"/a";', proto="http")
        self.assertIsNone(why)
        self.assertNotIn("app.http", out)


class Loadable(unittest.TestCase):
    """The translator's output must actually load."""

    @classmethod
    def setUpClass(cls):
        target = os.environ.get("ARGUS_TARGET_DIR", os.path.join(ROOT, "target-verify"))
        env = dict(os.environ, CARGO_TARGET_DIR=target)
        subprocess.run(["cargo", "build", "--release"], cwd=ROOT, check=True, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.exe = os.path.join(target, "release", "argus.exe" if os.name == "nt" else "argus")

    def check(self, *bodies, proto="http"):
        rules = [S.convert(rule(b, proto), HOME)[0] for b in bodies]
        self.assertTrue(all(rules), "translation refused a rule the test expected to convert")
        with tempfile.NamedTemporaryFile("w", suffix=".rules", delete=False, encoding="utf-8") as f:
            f.write("\n".join(rules) + "\n")
        try:
            proc = subprocess.run([self.exe, "-check-rules", f.name], capture_output=True, text=True)
        finally:
            os.unlink(f.name)
        self.assertEqual(proc.returncode, 0, proc.stdout)

    def test_every_shape_the_translator_emits_loads(self):
        self.check(
            'http.uri; content:"a"; pcre:"/a.b/i";',
            'http.uri; content:"/a"; pcre:"/b+/R";',
            'http.uri; content:"foo"; pcre:"/foo(?!bar)/";',
            'http.uri; content:"b"; pcre:"/(a+)b\\1/";',
            'http.uri; content:"foo"; pcre:"/\\bfoo(?!x)/";',
            'http.uri; content:"/a"; http.header; content:"b"; http.stat_code; content:"200";',
            'http.header_names; content:"|0d 0a|Host|0d 0a|";',
            'content:"x"; pcre:"/[sS[eE]x\\x2/U";',
            'http.uri; to_lowercase; content:"/admin"; pcre:"/a[0-9]+/";',
            'http.uri; content:"/gate.php"; http.header_names; content:!"|0d 0a|Accept|0d 0a|";',
            'http.method; content:"POST"; http.uri; content:"/x"; urilen:3<>20;',
            'http.uri.raw; url_decode; content:"../";',
            'http.header; header_lowercase; content:"host|3a 20|x"; http.uri; content:"/a";',
            'http.response_body; strip_whitespace; content:"abc";',
            'content:"abc"; threshold:type both, track by_dst, count 5, seconds 30;',
            'http.uri; content:"/a"; http.host; content:"h"; detection_filter:track by_src, count 3, seconds 10;',
            'http.uri; content:"x"; content:"abc"; offset:2; endswith;',
        )
        # dsize and isdataat on the raw payload are transport rules, not
        # application-layer ones.
        self.check('dsize:>20; content:"|de ad be ef|";', 'content:"KEY="; isdataat:!4,relative;', 'content:"a"; byte_test:1,!&,128,6,relative;', proto="tcp")
        self.check('content:"|03 00|";', proto="rdp")
        self.check('flow:to_server; content:"|01 00|";', proto="dns")


if __name__ == "__main__":
    unittest.main(verbosity=1)
