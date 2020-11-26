"""
Topotest conftest.py file.
"""

from lib.topogen import get_topogen, diagnose_env
from lib.topotest import json_cmp_result
from lib.topolog import logger
import pytest

topology_only = False


def pytest_addoption(parser):
    """
    Add CLI options to the topology tester.
    --topology-only: Make pytest only run the setup_module() to setup the
                     topology without running any tests.
    --runall: Make pytest run all tests, including those marked skip_by_default
    """
    parser.addoption(
        "--topology-only",
        action="store_true",
        help="Only set up this topology, don't run tests",
    )
    parser.addoption(
        "--runall",
        action="store_true",
        help="Run all tests, including those disabled by default",
    )


def pytest_runtest_call():
    """
    This function must be run after setup_module(), it does standarized post
    setup routines. It is only being used for the 'topology-only' option.
    """
    global topology_only

    if topology_only:
        tgen = get_topogen()
        if tgen is not None:
            # Allow user to play with the setup.
            tgen.mininet_cli()

        pytest.exit("the topology executed successfully")


def pytest_assertrepr_compare(op, left, right):
    """
    Show proper assertion error message for json_cmp results.
    """
    json_result = left
    if not isinstance(json_result, json_cmp_result):
        json_result = right
        if not isinstance(json_result, json_cmp_result):
            return None

    return json_result.gen_report()


def pytest_configure(config):
    "Assert that the environment is correctly configured."

    global topology_only

    if not diagnose_env():
        pytest.exit("enviroment has errors, please read the logs")

    if config.getoption("--topology-only"):
        topology_only = True

    config.addinivalue_line(
        "markers", "skip_by_default: mark test as to be run only on request"
    )


def pytest_runtest_makereport(item, call):
    "Log all assert messages to default logger with error level"
    # Nothing happened
    if call.excinfo is None:
        return

    parent = item.parent
    modname = parent.module.__name__

    # Treat skips as non errors
    if call.excinfo.typename != "AssertionError":
        logger.info(
            'assert skipped at "{}/{}": {}'.format(
                modname, item.name, call.excinfo.value
            )
        )
        return

    # Handle assert failures
    parent._previousfailed = item
    logger.error(
        'assert failed at "{}/{}": {}'.format(modname, item.name, call.excinfo.value)
    )

    # (topogen) Set topology error to avoid advancing in the test.
    tgen = get_topogen()
    if tgen is not None:
        # This will cause topogen to report error on `routers_have_failure`.
        tgen.set_error("{}/{}".format(modname, item.name))


def pytest_collection_modifyitems(config, items):
    if config.getoption("--runall"):
        # --runall given in CLI: don't skip test cases decorated using
        # @pytest.mark.skip_by_default
        # and modules containing
        # pytestmark = pytest.mark.skip_by_default
        return
    skip_marker = pytest.mark.skip(reason="need --runall option to run")
    for item in items:
        if "skip_by_default" in item.keywords:
            item.add_marker(skip_marker)
