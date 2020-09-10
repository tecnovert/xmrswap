import unittest

import tests.xmrswap.test_other as test_other
import tests.xmrswap.test_run as test_run
import tests.xmrswap.test_part as test_part


def test_suite():
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(test_other)
    suite.addTests(loader.loadTestsFromModule(test_run))
    suite.addTests(loader.loadTestsFromModule(test_part))

    return suite
