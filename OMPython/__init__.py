# -*- coding: utf-8 -*-
"""
OMPython is a Python interface to OpenModelica.
To get started on a local OMC server, create an OMCSessionLocal object:

```
import OMPython
omc = OMPython.OMCSessionLocal()
omc.sendExpression("command")
```

"""

from OMPython.ModelExecution import (
    ModelExecutionCmd,
    ModelExecutionData,
    ModelExecutionException,
)
from OMPython.ModelicaSystem import (
    ModelicaSystem,
)
from OMPython.ModelicaSystemBase import (
    LinearizationResult,
    ModelicaSystemBase,
    ModelicaSystemError,
)
from OMPython.ModelicaSystemDoE import (
    ModelicaSystemDoE,
)
from OMPython.ModelicaSystemRunner import (
    ModelicaSystemRunner,
)
from OMPython.OMCSession import (
    OMCSessionException,

    OMCSessionZMQ,

    OMCPath,
    OMCPathDummy,

    OMCSession,
    OMCSessionDocker,
    OMCSessionDockerContainer,
    OMCSessionDummy,
    OMCSessionLocal,
    OMCSessionPort,
    OMCSessionWSL,
)

# global names imported if import 'from OMPython import *' is used
__all__ = [
    'LinearizationResult',

    'ModelicaSystemBase',
    'ModelicaSystem',
    'ModelicaSystemDoE',
    'ModelicaSystemError',
    'ModelicaSystemRunner',

    'ModelExecutionCmd',
    'ModelExecutionData',
    'ModelExecutionException',

    'OMCSessionException',

    'OMCSessionZMQ',

    'OMCPath',
    'OMCPathDummy',

    'OMCSession',
    'OMCSessionDocker',
    'OMCSessionDockerContainer',
    'OMCSessionDummy',
    'OMCSessionLocal',
    'OMCSessionPort',
    'OMCSessionWSL',
]
