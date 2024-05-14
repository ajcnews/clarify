import datetime
import pytest

import lxml.etree

from clarify.parser import (Parser, ResultJurisdiction)


class TestParser():

    def test__underscore_to_camel(self):
        assert Parser._underscore_to_camel("") == ""
        assert Parser._underscore_to_camel("test") == "test"
        assert Parser._underscore_to_camel("test_again") == "testAgain"
        assert Parser._underscore_to_camel("test_again_but_longer") == "testAgainButLonger"
        assert Parser._underscore_to_camel("_test_again") == "TestAgain"  # XXX: Is this what we expect?
        assert Parser._underscore_to_camel("testing_123") == "testing123"
        assert Parser._underscore_to_camel("testing_123_again") == "testing123Again"

    def test__parse_result_jurisdiction(self):
        tag_name = "County"
        attributes = {
            "name": "Arkansas",
            "totalVoters": "10196",
            "ballotsCast": "5137",
            "voterTurnout": "50.38",
            "percentReporting": "100.00",
            "precinctsParticipating": "30",
            "precinctsReported": "30",
            "precinctsReportingPercent": "100.00",
        }

        result_jurisdiction_element = lxml.etree.Element(tag_name, attributes)

        result_jurisdiction = Parser._parse_result_jurisdiction(result_jurisdiction_element)

        assert isinstance(result_jurisdiction, ResultJurisdiction)

        assert hasattr(result_jurisdiction, "level")
        assert hasattr(result_jurisdiction, "name")
        assert hasattr(result_jurisdiction, "total_voters")
        assert hasattr(result_jurisdiction, "ballots_cast")
        assert hasattr(result_jurisdiction, "voter_turnout")
        assert hasattr(result_jurisdiction, "percent_reporting")
        assert hasattr(result_jurisdiction, "precincts_participating")
        assert hasattr(result_jurisdiction, "precincts_reported")
        assert hasattr(result_jurisdiction, "precincts_reporting_percent")

        assert result_jurisdiction.level == tag_name.lower()
        assert result_jurisdiction.name == attributes["name"]
        assert result_jurisdiction.total_voters == int(attributes["totalVoters"])
        assert result_jurisdiction.ballots_cast == int(attributes["ballotsCast"])
        assert result_jurisdiction.voter_turnout == float(attributes["voterTurnout"])
        assert result_jurisdiction.percent_reporting == float(attributes["percentReporting"])
        assert result_jurisdiction.precincts_participating == float(attributes["precinctsParticipating"])
        assert result_jurisdiction.precincts_reported == float(attributes["precinctsReported"])
        assert result_jurisdiction.precincts_reporting_percent == float(attributes["precinctsReportingPercent"])

    def test__get_or_create_result_jurisdiction(self):
        result_jurisdiction_name = "Test"
        result_jurisdiction_element = lxml.etree.Element("County", { "name": result_jurisdiction_name })
        result_jurisdiction = Parser._parse_result_jurisdiction(result_jurisdiction_element)

        parser = Parser()

        assert parser._result_jurisdictions == []
        assert parser._result_jurisdiction_lookup == {}

        # Test the "create" part.
        parser._get_or_create_result_jurisdiction(result_jurisdiction_element)

        assert parser._result_jurisdictions == [ result_jurisdiction ]
        assert parser._result_jurisdiction_lookup == { result_jurisdiction_name: result_jurisdiction }

        # Test the "get" part.
        parser._get_or_create_result_jurisdiction(result_jurisdiction_element)

        assert parser._result_jurisdictions == [ result_jurisdiction ]
        assert parser._result_jurisdiction_lookup == { result_jurisdiction_name: result_jurisdiction }

    def test_add_result_jurisdiction(self):
        result_jurisdiction_name = "Test"
        result_jurisdiction = ResultJurisdiction(
            name=result_jurisdiction_name,
            total_voters=0,
            ballots_cast=0,
            voter_turnout=100.0,
            percent_reporting=100.0,
            precincts_participating=0,
            precincts_reported=0,
            precincts_reporting_percent=100.0,
            level="county",
        )

        parser = Parser()

        assert parser._result_jurisdictions == []
        assert parser._result_jurisdiction_lookup == {}

        parser.add_result_jurisdiction(result_jurisdiction)

        assert parser._result_jurisdictions == [ result_jurisdiction ]
        assert parser._result_jurisdiction_lookup == { result_jurisdiction_name: result_jurisdiction }


class TestPrecinctParser():
    def test_parse(self):
        num_precincts = 33
        num_candidates = 5
        # Overvotes and undervotes
        num_pseudo_candidates = 2
        num_expected_results = (
            num_candidates * (num_precincts + 1) +
            num_pseudo_candidates * (num_precincts + 1)
        )

        er = Parser()
        er.parse('tests/data/precinct.xml')

        assert er.timestamp.replace(tzinfo=None) == datetime.datetime(2014, 5, 20, 20, 19, 21)
        assert er.election_name == "2014 Primary Election"
        assert er.election_date == datetime.date(2014, 5, 20)
        assert er.region == "Greenup"
        assert er.total_voters == 28162
        assert er.ballots_cast == 5926
        assert er.voter_turnout == 21.04

        assert len(er.result_jurisdictions) == num_precincts
        precinct = next(p for p in er.result_jurisdictions if p.name == 'A105')
        assert precinct.total_voters == 0
        assert precinct.ballots_cast == 171
        assert precinct.voter_turnout == 0
        assert precinct.percent_reporting == 4

        assert len(er.contests) == 1

        assert len(er.results) == num_expected_results

        result_jurisdiction_name = "A105"
        result_jurisdiction = er.get_result_jurisdiction(result_jurisdiction_name)

        assert str(result_jurisdiction) == result_jurisdiction_name
        assert result_jurisdiction.name == result_jurisdiction_name
        assert result_jurisdiction.total_voters == 0
        assert result_jurisdiction.ballots_cast == 171
        assert result_jurisdiction.voter_turnout == 0
        assert result_jurisdiction.percent_reporting == 4

        assert result_jurisdiction == precinct

        contest_text = "US Senator - REPUBLICAN"
        contest = er.get_contest(contest_text)

        assert str(contest) == contest_text
        assert contest.text == contest_text
        assert contest.key == "4"
        assert contest.vote_for == 1
        assert not contest.is_question
        assert contest.precincts_reporting == 32
        assert contest.precincts_reported == 32

        contest_choice_text = "Matt BEVIN"
        contest_choice = contest.choices[0]

        assert contest_choice.contest == contest

        assert str(contest_choice) == contest_choice_text
        assert contest_choice.text == contest_choice_text
        assert contest_choice.key == "1"
        assert contest_choice.total_votes == 820


class TestCountyParser():

    def test_parse(self):
        num_counties = 75
        num_candidates = 1
        # Election
        num_vote_types = 4
        num_expected_results = (
            (num_vote_types * num_counties * num_candidates) +
            (num_vote_types * num_candidates)
        )

        er = Parser()
        er.parse('tests/data/county.xml')

        assert er.timestamp.replace(tzinfo=None) == datetime.datetime(2014, 11, 13, 14, 58, 41)
        assert er.election_name == "2014 General Election"
        assert er.election_date == datetime.date(2014, 11, 4)
        assert er.region == "AR"
        assert er.total_voters == 1690577
        assert er.ballots_cast == 850615
        assert er.voter_turnout == 50.32

        assert len(er.result_jurisdictions) == num_counties
        county = next(c for c in er.result_jurisdictions if c.name == 'Arkansas')
        assert county.total_voters == 10196
        assert county.ballots_cast == 5137
        assert county.voter_turnout == 50.38
        assert county.precincts_participating == 30
        assert county.precincts_reporting_percent == 100.0

        assert len(er.contests) == 1

        assert len(er.results) == num_expected_results

        result_jurisdiction_name = "Arkansas"
        result_jurisdiction = er.get_result_jurisdiction(result_jurisdiction_name)

        assert str(result_jurisdiction) == result_jurisdiction_name
        assert result_jurisdiction.name == result_jurisdiction_name
        assert result_jurisdiction.total_voters == 10196
        assert result_jurisdiction.ballots_cast == 5137
        assert result_jurisdiction.voter_turnout == 50.38
        assert result_jurisdiction.precincts_participating == 30
        assert result_jurisdiction.precincts_reported == 30
        assert result_jurisdiction.precincts_reporting_percent == 100.0

        assert result_jurisdiction == county

        contest_text = "U.S. Senate"
        contest = er.get_contest(contest_text)

        assert str(contest) == contest_text
        assert contest.text == contest_text
        assert contest.key == "100"
        assert contest.vote_for == 1
        assert not contest.is_question
        assert contest.counties_participating == 75
        assert contest.counties_reported == 75
        assert contest.precincts_participating == 2655
        assert contest.precincts_reported == 2655

        contest_choice_text = "Tom Cotton"
        contest_choice = contest.choices[0]

        assert contest_choice.contest == contest

        assert str(contest_choice) == contest_choice_text
        assert contest_choice.text == contest_choice_text
        assert contest_choice.key == "001"
        assert contest_choice.party == "REP"
        assert contest_choice.total_votes == 477734
