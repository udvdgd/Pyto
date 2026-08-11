# Host-runnable unit tests

The tests in `PytoTests/Tests/python/unit` cover the pure Python parts of `Lib`
and run on any desktop Python 3.10+, without an iOS device or simulator.

```
$ pip install pytest coverage
$ python -m pytest PytoTests/Tests/python/unit
$ python -m coverage run --source Lib -m pytest PytoTests/Tests/python/unit && python -m coverage report
```

`conftest.py` puts `Lib` on `sys.path` and provides fixtures that install fake
`rubicon.objc`, `pyto`, `userkeys` and `sharing` modules so that modules
depending on the Objective-C runtime can still be imported and exercised.

The tests under `PytoTests/Tests/python` (outside this directory) are integration
tests that must be run from inside the app.
