from setuptools import setup, Extension

my_arrays_module = Extension(
    'my_arrays',                # The name of the module
    sources=['my_arrays.c']     # The list of C source files
)

setup(
    name='MyArrays',
    version='1.0',
    description='',
    ext_modules=[my_arrays_module]
)