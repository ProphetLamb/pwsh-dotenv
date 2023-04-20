# dotenv for pwsh

Fully fleshed out .env file utilities written in pwsh.

## Quickstart

Download the single all-in-one script.

```bash
iwr https://raw.githubusercontent.com/ProphetLamb/pwsh-dotenv/main/dotenv.ps1 -o dotenv.ps1
```

For usage in automation the module provides an API similar to [dotenv-cli](https://github.com/entropitor/dotenv-cli).

```pwsh
# load the module
. ./dotenv.ps1
# store the PRIVATE_KEY from the .env or .env.local into cert.priv
dotenv -p PRIVATE_KEY > cert.priv
# load the .env.development over the .env
# execute myapp with the variables (highest wins):
# System > .env > .env.development > .env.local > .env.development.local > HOST_URL=...
dotenv -v HOST_URL=https://localhost:8081 -c development myapp.exe
# when no command is provided exports them to the current process
dotenv -v HOST_URL=https://localhost:8081 -c development
```

For usage in scripting or development please refer to the functions described in [Usage](#usage).

Examples can be found in the [tests](dotenv.Tests.ps1).

## Usage

This script is used to install dotenv as a module in the current session or permanently.

```pwsh
# load into session
. ./dotenv.ps1
# install to user profile
. ./dotenv.ps1 -Install CurrentUser
# install to maschine (requires elevated privileges)
. ./dotenv.ps1 -Install LocalMachine
```

The functions provided by the module are described in the following sections.

### Import-Env

Import environment variables from a .env file into memory.

The .env file should be a list of lines in the format of KEY=VALUE.
Variables denoted by $ are interpreted as environment variables. This occurs recursively.
Comments are denoted by # and are ignored.

Consumes files or file content.
Produces a `[System.Collections.Generic.Dictionary[string, string]]`.

For more information see:

```pwsh
man Import-Env
```

#### Example file

The following snippet illustrates a file parsed by `Import-Env`.

```bash
# Unquoted
Hello=World
# Clear the variable
Hello=
# Double quoted
Multi="Line\"\nString"
# Unquoted, Variable, Tailing comment
WhiteSpace = None $Hello # Inline Comment
# Double quoted, Variable
DoubleQuote="${Multi}Value"
# Double quoted, Multiline, Variable
DoubleQuoteMultiline="""
asdasd
asdasd # Not A Comment
asdasd
$DoubleQuote
"""
# Unicode
Unicode=äöüß
# Single quoted, no escape sequences
SingleQuote='\n\o\t \e\s\c\a\p\e\d' # A comment'
# Single quoted, no variable
SingleQuoteNoVar='$Hello'
# Single quoted, multiline
PRIVATE_KEY='''
-----BEGIN RSA PRIVATE KEY-----
...
HkVN9...
...
-----END DSA PRIVATE KEY-----
'''                   # One leading and tailing line break is removed
=HIDDEN=DISSALLOWED   # This is ignored
AnotherVariable=Hello # This is a comment
```

### Export-Env

Export the key-value pairs from memory to the specified target.

The key-value pairs are exported to the specified target. For environment variables that can be the scopes process, user, or machine.
For the pipe target, the key-value pairs are piped to the next command using the Success (1) stream.

Consumes a `[System.Collections.Generic.Dictionary[string, string]]`.
Produces environment variables or text.

For more information see:

```pwsh
man Export-Env
```

### Use-Env

Executes a command with the specified environment variables.

Ensures that the current environment variables are restored after the command is executed, even if the command fails.

Consumes a `[System.Collections.Generic.Dictionary[string, string]]`.
Produces the command output.

For more information see:

```pwsh
man Use-Env
```

### dotenv

dotenv-cli like tool.

Internally uses the functions Import-Env, Export-Env, Use-Env to provide an interface simmilar to dotenv-cli

For more information see:

```pwsh
man dotenv
```
