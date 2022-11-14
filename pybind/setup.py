#/bin/python3 
# -*- coding: utf-8 -*-

from setuptools import setup, Extension

"""
functions_module = Extension(
    name = 'Unit8List', 
    sources = ['function_wrapper.cpp'],
    include_dirs = [r'/usr/include']
    )

setup(ext_modules = [functions_module])
"""
functions_module = Extension(  
    name = 'py2cpp',  
    sources = ['function_wrapper.cpp'],  
    include_dirs = [r'/usr/include']  
)  
  
setup(ext_modules = [functions_module])