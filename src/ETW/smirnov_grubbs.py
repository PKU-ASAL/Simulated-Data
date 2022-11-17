# -*- coding: utf-8 -*-
"""
Smirnov-Grubbs test for outlier detection.
"""

import numpy as np
from scipy import stats
from math import sqrt
from collections import defaultdict

try:
    import pandas as pd
except ImportError:
    pd = None

__all__ = ['test',
           'two_sided_test',
           'two_sided_test_indices',
           'two_sided_test_outliers',
           'min_test',
           'min_test_indices',
           'min_test_outliers',
           'max_test',
           'max_test_indices',
           'max_test_outliers',
           'TwoSidedGrubbsTest',
           'MinValueGrubbsTest',
           'MaxValueGrubbsTest',
           'OutputType']


DEFAULT_ALPHA = 0.95


# Test output types
class OutputType:
    DATA = 0  # Output data without outliers
    OUTLIERS = 1  # Output outliers
    INDICES = 2  # Output outlier indices


class GrubbsTest(object):
    def __init__(self, data):
        self.original_data = data

    def _copy_data(self):
        if isinstance(self.original_data, np.ndarray):
            return self.original_data
        elif pd is not None and isinstance(self.original_data, pd.Series):
            return self.original_data
        elif isinstance(self.original_data, list):
            return np.array(self.original_data)
        else:
            raise TypeError('Unsupported data format')

    def _delete_item(self, data, index):
        if pd is not None and isinstance(data, pd.Series):
            return data.drop(index)
        elif isinstance(data, np.ndarray):
            return np.delete(data, index)
        else:
            raise TypeError('Unsupported data format')

    def _get_indices(self, values):
        last_seen = defaultdict(lambda: 0)
        data = list(self.original_data)
        indices = list()
        for value in values:
            start = last_seen[value]
            index = data.index(value, start)
            indices.append(index)
            last_seen[value] = index + 1
        return indices

    def _get_g_test(self, data, alpha):
        """Compute a significant value score following these steps, being alpha
        the requested significance level:
        1. Find the upper critical value of the t-distribution with n-2
           degrees of freedom and a significance level of alpha/2n
           (for two-sided tests) or alpha/n (for one-sided tests).
        2. Use this t value to find the score with the following formula:
           ((n-1) / sqrt(n)) * (sqrt(t**2 / (n-2 + t**2)))
        :param numpy.array data: data set
        :param float alpha: significance level
        :return: G_test score
        """
        n = len(data)
        significance_level = self._get_t_significance_level(alpha, n)
        t = stats.t.isf(significance_level, n-2)
        return ((n-1) / sqrt(n)) * (sqrt(t**2 / (n-2 + t**2)))

    def _test_once(self, data, alpha):
        """Perform one iteration of the Smirnov-Grubbs test.
        :param numpy.array data: data set
        :param float alpha: significance level
        :return: the index of the outlier if one if found; None otherwise
        """
        target_index, value = self._target(data)

        g = value / data.std()
        g_test = self._get_g_test(data, alpha)
        return target_index if g > g_test else None

    def run(self, alpha=DEFAULT_ALPHA, output_type=OutputType.DATA):
        """Run the Smirnov-Grubbs test to remove outliers in the given data set.
        :param float alpha: significance level
        :param int output_type: test output type (from OutputType class values)
        :return: depending on the value of output_type, the data set without
        outliers (DATA), the outliers themselves (OUTLIERS) or the indices of
        the outliers in the original data set (INDICES)
        """
        data = self._copy_data()
        outliers = list()

        while True:
            outlier_index = self._test_once(data, alpha)
            if outlier_index is None:
                break
            outlier = data[outlier_index]
            outliers.append(outlier)
            data = self._delete_item(data, outlier_index)

        return_value = data
        if output_type == OutputType.OUTLIERS:
            return_value = outliers
        elif output_type == OutputType.INDICES:
            return_value = self._get_indices(outliers)
        return return_value

    def _target(self, data):
        raise NotImplementedError

    def _get_t_significance_level(self, alpha):
        raise NotImplementedError


class TwoSidedGrubbsTest(GrubbsTest):
    def _target(self, data):
        """Compute the index of the farthest value from the sample mean and its
        distance.
        :param numpy.array data: data set
        :return int, float: the index of the element and its distance to the
        mean
        """
        relative_values = abs(data - data.mean())
        index = relative_values.argmax()
        value = relative_values[index]
        return index, value

    def _get_t_significance_level(self, alpha, n):
        return alpha / (2*n)


class OneSidedGrubbsTest(GrubbsTest):
    def _target(self, data):
        """Compute the index of the min/max value and its distance from the
        sample mean.
        :param numpy.array data: data set
        :return int, float: the index of the min/max value and its distance to
        the mean
        """
        index = self._get_index(data)
        value = data[index]
        return index, abs(value - data.mean())

    def _get_t_significance_level(self, alpha, n):
        return alpha / n


class MinValueGrubbsTest(OneSidedGrubbsTest):
    def _get_index(self, data):
        return data.argmin()


class MaxValueGrubbsTest(OneSidedGrubbsTest):
    def _get_index(self, data):
        return data.argmax()


# Convenience functions to run single Grubbs tests

def _test(test_class, data, alpha, output_type):
    return test_class(data).run(alpha, output_type=output_type)


def _two_sided_test(data, alpha, output_type):
    return _test(TwoSidedGrubbsTest, data, alpha, output_type)


def _min_test(data, alpha, output_type):
    return _test(MinValueGrubbsTest, data, alpha, output_type)


def _max_test(data, alpha, output_type):
    return _test(MaxValueGrubbsTest, data, alpha, output_type)


def two_sided_test(data, alpha=DEFAULT_ALPHA):
    return _two_sided_test(data, alpha, OutputType.DATA)


def two_sided_test_indices(data, alpha=DEFAULT_ALPHA):
    return _two_sided_test(data, alpha, OutputType.INDICES)


def two_sided_test_outliers(data, alpha=DEFAULT_ALPHA):
    return _two_sided_test(data, alpha, OutputType.OUTLIERS)


def min_test(data, alpha=DEFAULT_ALPHA):
    return _min_test(data, alpha, OutputType.DATA)


def min_test_indices(data, alpha=DEFAULT_ALPHA):
    return _min_test(data, alpha, OutputType.INDICES)


def min_test_outliers(data, alpha=DEFAULT_ALPHA):
    return _min_test(data, alpha, OutputType.OUTLIERS)


def max_test(data, alpha=DEFAULT_ALPHA):
    return _max_test(data, alpha, OutputType.DATA)


def max_test_indices(data, alpha=DEFAULT_ALPHA):
    return _max_test(data, alpha, OutputType.INDICES)


def max_test_outliers(data, alpha=DEFAULT_ALPHA):
    return _max_test(data, alpha, OutputType.OUTLIERS)


def test(data, alpha=DEFAULT_ALPHA):
    return two_sided_test(data, alpha)