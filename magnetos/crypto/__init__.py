# -*- coding: utf-8 -*-
# Created by restran on 2016/9/28
from __future__ import unicode_literals, absolute_import
from mountains.utils import PrintCollector


def smart_output(result=None, verbose=False, p=None):
    if verbose:
        if isinstance(p, PrintCollector):
            return p.all_output()

    return result
