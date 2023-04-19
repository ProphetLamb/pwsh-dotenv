#!/usr/bin/env pwsh
<#
.SYNOPSIS
This script is used to install dotenv as a module in the current session or permanently
.DESCRIPTION
Using the options Install and Uninstall, allows the user to install and uninstall dotenv as a powershell module to either the current user or local machine
Elevated privileges are required to install to the local machine
.PARAMETER Install
Install the module to the current user or local machine
.PARAMETER Uninstall
Uninstall the module from the current user or local machine
.EXAMPLE
. ./dotenv.ps1
Load dotenv for the current session
.EXAMPLE
. ./dotenv.ps1 -Install CurrentUser
Install dotenv to user profile
.EXAMPLE
. ./dotenv.ps1 -Install LocalMachine
Install dotenv to maschine#
.EXAMPLE
. ./dotenv.ps1 -InstallModulePath ".\MyModules" && Import-Module .\MyModules\dotenv
Install dotenv to the specified directory and load it for the current session
.EXAMPLE
. ./dotenv.ps1 -Uninstall CurrentUser
Uninstall dotenv from user profile
.EXAMPLE
. ./dotenv.ps1 -Uninstall LocalMachine
Uninstall dotenv from maschine
.EXAMPLE
Remove-Module dotenv && . ./dotenv.ps1 -UninstallModulePath ".\MyModules"
Uninstall dotenv from the specified directory
#>
[CmdletBinding()]
Param(
	[Parameter(Mandatory = $false)][ValidateSet("LocalMachine", "CurrentUser")][string] $Install,
	[Parameter(Mandatory = $false)][ValidateSet("LocalMachine", "CurrentUser")][string] $Uninstall,
	[Parameter(Mandatory = $false)][ValidateScript({ if (-not ($_ | Test-Path -PathType Container)) { throw "The directory '$_' does not exist" } $true })][System.IO.DirectoryInfo] $InstallModulePath = $null,
	[Parameter(Mandatory = $false)][ValidateScript({ if (-not ($_ | Test-Path -PathType Container)) { throw "The directory '$_' does not exist" } $true })][System.IO.DirectoryInfo] $UninstallModulePath = $null
)

###############################################################################
###= dotenv\dotenv.psd1
###############################################################################
# Copyright (c) 2023, ProphetLamb
# Dotenv for Powershell https://github.com/ProphetLamb/pwsh-dotenv/ dual licensed under the MIT & APACHE 2.0 License at your option

@{
	ModuleVersion     = '0.1.0'
	RootModule        = 'dotenv.psm1'
	FunctionsToExport = @(
		'Import-Env',
		'Export-Env',
		'Use-Env',
		'dotenv'
	)
	Author            = 'ProphetLamb'
	Copyright         = '(c) 2023, ProphetLamb'
	Description       = 'Dotenv for Powershell'
	PowerShellVersion = '5.1'
	PrivateData       = @{
		PSData = @{
			Tags       = @('dotenv', 'env', 'environment', 'environment variables')
			ProjectUri = 'https://github.com/ProphetLamb/pwsh-dotenv'
		}
	}
}

###############################################################################
###=
###############################################################################
# Copyright (c) 2023, ProphetLamb
# Dotenv for Powershell https://github.com/ProphetLamb/pwsh-dotenv/ dual licensed under the MIT & APACHE 2.0 License at your option
# Copyright (c) 2019, Johannes Passing
# Self installation https://github.com/jpassing/powershell-install-as-module/ licensed under the APACHE 2.0 License
$_file_delimiter_regex = [System.Text.RegularExpressions.Regex]::new(@'
(?si)##[#]+\s*?\n###=\s*(?<file_name>[^\n]*?)\n##[#]+\s*?\n?
'@, [System.Text.RegularExpressions.RegexOptions]::Compiled + [System.Text.RegularExpressions.RegexOptions]::CultureInvariant + [System.Text.RegularExpressions.RegexOptions]::ExplicitCapture)

function Install-ScriptAsModule {
	<#
	.SYNOPSIS
	Generate a Powershell module from this script and install it.
	#>
	Param(
		[Parameter(Mandatory = $True, Position = 0)][System.IO.DirectoryInfo]$ModulePath
	)

	function _add_content_to_filebuffer([System.Collections.Generic.Dictionary[string, [System.Text.StringBuilder]]] $file_buffers, [string] $file_name, [string] $file_content) {
		$file_content = $file_content.Trim()
		$file_name = $file_name.Trim()
		if (-not $file_content -or -not $file_name) {
			return
		}
		# get or create the buffer for the file
		$file_buffer = $file_buffers[$file_name]
		if (-not $file_buffer) {
			$file_buffer = [System.Text.StringBuilder]::new()
			[void]$file_buffers.Add($file_name, $file_buffer)
		}
		# append the content of the file
		[void]$file_buffer.Append($file_content)
	}

	$master_file_content = Get-Content $script:MyInvocation.MyCommand.Path -Raw -Encoding UTF8
	# $master_file_content = Get-Content 'D:\source\repos\pwsh-dotenv\dotenv.ps1' -Raw -Encoding UTF8
	[System.Text.RegularExpressions.MatchCollection] $file_delimiter_matches = $_file_delimiter_regex.Matches($master_file_content)
	$file_buffers = [System.Collections.Generic.Dictionary[string, [System.Text.StringBuilder]]]::new()
	$partial_file_name = $null
	$master_file_start = 0

	foreach ($file_delimiter in $file_delimiter_matches.GetEnumerator()) {
		$file_delimiter_start = $file_delimiter.Index
		$file_delimiter_end = $file_delimiter_start + $file_delimiter.Length
		$partial_file_content = $master_file_content.Substring($master_file_start, $file_delimiter_start - 1 - $master_file_start)
		# from $master_file_start to $file_delimiter_start is the content of the previous file
		_add_content_to_filebuffer $file_buffers $partial_file_name $partial_file_content
		$master_file_start = $file_delimiter_end
		$partial_file_name = $file_delimiter.Groups["file_name"].Value
	}
	# add the remaining content of the master file
	_add_content_to_filebuffer $file_buffers $partial_file_name $master_file_content.Substring($master_file_start)

	foreach ($file_and_content in $file_buffers.GetEnumerator()) {
		$file_name = $file_and_content.Key
		Write-Debug "Creating '$file_name'"
		$file_content = $file_and_content.Value.ToString()
		$full_file_path = Join-Path -Path $ModulePath.FullName -ChildPath $file_name
		[void][System.IO.Directory]::CreateDirectory((Split-Path -Path $full_file_path -Parent))
		$file_content | Out-File -FilePath $full_file_path -Encoding UTF8 -Force
	}
	Write-Debug "Installation to '$ModulePath' complete"
}

function Uninstall-ScriptAsModule {
	<#
			.SYNOPSIS
					Remove Powershell module that has been generated from this script.
	#>
	Param(
		[Parameter(Mandatory = $True, Position = 0)][System.IO.DirectoryInfo]$ModulePath
	)

	$master_file_content = Get-Content $script:MyInvocation.MyCommand.Path -Raw -Encoding UTF8
	[System.Text.RegularExpressions.MatchCollection] $file_delimiter_matches = $_file_delimiter_regex.Matches($master_file_content)
	foreach ($file_delimiter in $file_delimiter_matches.GetEnumerator()) {
		$file_name = $file_delimiter.Groups["file_name"].Value
		if (-not $file_name) {
			continue
		}
		Write-Debug "Removing '$file_name'"
		$full_file_path = Join-Path -Path $ModulePath.FullName -ChildPath $file_name
		if (Test-Path -Path $full_file_path) {
			Remove-Item -Force -Path $full_file_path
		}
	}
	Write-Debug "Uninstallation from '$ModulePath' complete"
}

# check for the presence of windows powershell and powershell core
# install the module to all available locations
function _validate_module_dirs([string[]] $module_dirs) {
	foreach ($dir in $module_dirs | ForEach-Object { [System.IO.Path]::GetFullPath($_) } | Select-Object -Unique) {
		[System.IO.DirectoryInfo] $dir = [System.IO.DirectoryInfo]::new($dir)
		if (-not $dir.Parent.Exists) {
			Write-Debug "Powershell installation not found at '$dir'"
			continue
		}
		if ($dir.Exists) {
			$dir
		}
		Write-Debug "Creating module directory '$dir'"
		try {
			[void]$dir.Create()
		}
		catch {
			Write-Debug "Failed to create module directory '$dir'"
			continue
		}
		$dir
	}
}
$_pwsh_module_dirs = @{
	LocalMachine = _validate_module_dirs @(
		(Join-Path -Path $Env:ProgramFiles -ChildPath "WindowsPowerShell\Modules\"),
		(Join-Path -Path $Env:ProgramFiles -ChildPath "PowerShell\$($PSVersionTable.PSVersion.Major)\Modules\"),
		$PSHOME
	)
	CurrentUser  = _validate_module_dirs @(
		(Join-Path -Path ([environment]::getfolderpath("mydocuments")) -ChildPath "WindowsPowerShell\Modules\"),
		(Join-Path -Path ([environment]::getfolderpath("mydocuments")) -ChildPath "PowerShell\Modules\")
	)
}

Write-Debug "Exported functions added to current session."

foreach ($directory in $_pwsh_module_dirs[$Uninstall]) {
	Uninstall-ScriptAsModule $directory
}
foreach ($directory in $_pwsh_module_dirs[$Install]) {
	Install-ScriptAsModule $directory
}
if ($UninstallModulePath) {
	Uninstall-ScriptAsModule $UninstallModulePath
}
if ($InstallModulePath) {
	Install-ScriptAsModule $InstallModulePath
}
if (-not $Install -and -not $Uninstall -and -not $InstallModulePath -and -not $UninstallModulePath) {
	Write-Debug "Use -Install to add functions permanenently."
}

###############################################################################
###= dotenv\dotenv.psm1
###############################################################################
# Copyright (c) 2023, ProphetLamb
# Dotenv for Powershell https://github.com/ProphetLamb/pwsh-dotenv/ dual licensed under the MIT & APACHE 2.0 License at your option

Set-StrictMode -Version Latest

function Get-OsSensitiveStringComparer {
	<#
	.SYNOPSIS
	Get a string comparer with case sensitivity depending on the current OS

	.DESCRIPTION
	Windows is case insensitive, Linux & MacOS are case sensitive
	#>
	[OutputType([System.Collections.Generic.IEqualityComparer[string]])]
	param()

	if ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
		[System.StringComparer]::InvariantCultureIgnoreCase
	}
	else {
		[System.StringComparer]::InvariantCulture
	}
}

enum ImportEnvExpand {
	Default
	Force
	Never
}

function Import-Env {
	<#
	.SYNOPSIS
	Import environment variables from a .env file into memory

	.DESCRIPTION
	The .env file should be a list of lines in the format of KEY=VALUE
	Variables denoted by $ are interpreted as environment variables. This occurs recursively
	Comments are denoted by # and are ignored.

	.PARAMETER File
	The name of the file, or an array of file names to load

	.PARAMETER Encoding
	The encoding of the file, if not specified the default is 'utf-8' see [System.Text.Encoding]::GetEncodings() for a list of encodings
	Same as Get-Content -Encoding

	.PARAMETER Raw
	Raw enables reading of arbitary string content from the pipeline. E.g. 'Get-Content .env -Raw -Encoding utf8 | Import-Env -Raw'
	If Raw is set:
	- The File parameter is expected to contain the string content in the correct (utf8) encoding.
	- The Encoding parameter is ignored.
	The user MUST ensure the content is NOT SPLIT by line breaks. This causes the parser to FAIL reading multiline values.
	This is achieved by e.g. passing the -Raw parameter to Get-Content.

	.PARAMETER Expand
	Expand determines if and how variables are expanded
	A variable is a string of the form $VAR or ${VAR} where VAR is a environment variable name
	Non existing environment variables are replaced with empty strings. A warning is emmited
	Variables are expanded recursively, i.e. if the replacement for a variable contains a variable, it is expanded as well. This occurs up a depth of 10, after which an error is emmited
	Expand can be one of three values:
	- Default: Variables are interpreted as descibed in the Notes section
	- Force: Variables are always expanded
	- Ignore: Variables are never expanded

	.PARAMETER IncludeSystemVariables
	IncludeSystemVariables determines if the current processs environment variables are merged with the imported variables
	If set all imported variables are added to the current process environment variables, existing variables are overwritten
	If not set only imported variables are returned

	.INPUTS
	The string[] of file names to import, same as the file_name parameter
	If Raw is set, the string content of the file(s) to import

	.OUTPUTS
	The success stream (1) is reserved for pipeline output, and will be used to pipe the environment variables to the next command
	The output is a stream of [System.Collections.Generic.KeyValuePair[string, string]] objects

	.LINK
	The specification of the .env format can be found at https://hexdocs.pm/dotenvy/dotenv-file-format.html

	.NOTES
	Contrary to dotenv, if no files are specified none are imported
	Variables are imported in the order of the files, later variables overwrite earlier variables

	Values can be one of three types, denoted by the quotation marks
	- Unquoted values: Escape sequences are disabled, Expressions are enabled
	- Single quoted values: Escape sequences are disabled, Expressions are diseabled
	- Double quoted values: Escape sequences are enabled, Expressions are enabled
	Use three consecutive quotes for multiline values, the leading and trailing line breaks are removed. The settings of the quotes used are applied

	.EXAMPLE
	Import-Env .env | Export-Env
	Imports the file '.env' and exports the variables into the Process environment

	.EXAMPLE
	.env | Import-Env
	Imports the file '.env' from the pipeline

	.EXAMPLE
	Import-Env -Raw 'KEY=VALUE', "KEY2=`"`nMultiline`nValue`""
	Imports the variable KEY and KEY2 from arguments

	.EXAMPLE
	'KEY=VALUE', "KEY2=`"`nMultiline`nValue`"" | Import-Env -Raw
	Imports the variable KEY and KEY2 from the pipeline

	.EXAMPLE
	See Export-Env for an example of how to use the output of Import-Env

	.EXAMPLE
	cat .env
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
  #>
	[OutputType([System.Collections.Generic.Dictionary[string, string]])]
	param (
		[Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)][Alias('f')]
		[string[]] $File,
		[Parameter(Mandatory = $false)][Alias('c')]
		$Encoding = 'utf8',
		[Parameter(Mandatory = $false)][Alias('r')]
		[switch] $Raw,
		[Parameter(Mandatory = $false)][Alias('e')]
		[ImportEnvExpand] $Expand = [ImportEnvExpand]::Default,
		[Parameter(Mandatory = $false)][Alias('m')]
		[switch] $IncludeSystemVariables
	)

	begin {
		$variables = [System.Collections.Generic.Dictionary[string, string]]::new((Get-OsSensitiveStringComparer))
		[int] $success_count = 0
		[string[]] $failures = @()

		if ($IncludeSystemVariables) {
			# GetEnvironmentVariables returns a IDictionary, not a IDictionary[string, string]
			# The key and value are [string]s
			# Validate keys and values, and convert to Dictionary[string, string]
			foreach ($key_value_pair in [System.Environment]::GetEnvironmentVariables().GetEnumerator()) {
				if ($key_value_pair.Key) {
					$variables[$key_value_pair.Key] = if ($key_value_pair.Value) { $key_value_pair.Value } else { $null }
				}
			}
		}
		##
		# Helper functions
		##
		enum ImportEnvValueType {
			Simple
			Interpolated
			Literal
		}

		function _unescape([string] $value, [ImportEnvValueType] $value_type) {
			function _unescape_core([string] $value) {
				# this should really be part of the dotnet runtime, somewhere...
				# Url decode incorrectly decodes some characters, e.g. % = %25
				# Regex decode does not decode all characters
				$sb = [System.Text.StringBuilder]::new($value.Length)
				[bool] $last_is_bs = $false
				for ([int] $pos = 0; $pos -lt $value.Length; $pos += 1) {
					[char] $c = $value[$pos]
					if ($last_is_bs) {
						switch ($c) {
							'a' { [void]$sb.Append([char]0x07) }
							'b' { [void]$sb.Append([char]0x08) }
							't' { [void]$sb.Append([char]0x09) }
							'n' { [void]$sb.Append([char]0x0a) }
							'v' { [void]$sb.Append([char]0x0b) }
							'f' { [void]$sb.Append([char]0x0c) }
							'r' { [void]$sb.Append([char]0x0d) }
							'x' {
								$pos += 2
								if ($pos -ge $value.Length) {
									throw "Invalid escape sequence: \x at end of string"
								}
								# hex escape sequence
								$hex = $value.SubString($sb.Length + 1, 2)
								$hex = [int]('0x' + $hex)
								[void]$sb.Append([char]$hex)
							}
							'u' {
								$pos += 4
								if ($pos -ge $value.Length) {
									throw "Invalid escape sequence: \u at end of string"
								}
								# unicode escape sequence
								$hex = $value.SubString($sb.Length + 1, 4)
								$hex = [int]('0x' + $hex)
								[void]$sb.Append([char]$hex)
							}
							'U' {
								$pos += 8
								if ($pos -ge $value.Length) {
									throw "Invalid escape sequence: \U at end of string"
								}
								# unicode escape sequence
								$hex = $value.SubString($sb.Length + 1, 8)
								$hex = [int]('0x' + $hex)
								# add the surrogate pair
								[void]$sb.Append([System.Char]::ConvertFromUtf32($hex))
							}
							default {
								[void]$sb.Append($c)
							}
						}
						$last_is_bs = $false
					}
					else {
						if ($c -eq '\') {
							$last_is_bs = $true
						}
						else {
							[void]$sb.Append($c)
						}
					}
				}
				if ($last_is_bs) {
					throw "Invalid escape sequence: \ at end of string"
				}
				return $sb.ToString()
			}

			if ($value_type -ne [ImportEnvValueType]::Interpolated) {
				return $value
			}
			return _unescape_core $value
		}

		function _get_env_var([string] $name) {
			if (-not $name -or $name -eq '') {
				return ''
			}
			# attempt to get the value from the $variables
			$value = $variables[$name]
			if ($null -ne $value) {
				return $value
			}
			# attempt to get the environment variable
			$value = [System.Environment]::GetEnvironmentVariable($name)
			if ($value) {
				return $value
			}
			Write-Warning "Environment variable '$name' does not exist. Assuming empty string."
			return ''
		}

		$expand_regex = [System.Text.RegularExpressions.Regex]::new(@'
(?<!\\)\$(?:{(?<var_box>[^}]+)}|(?<var_literal>[a-zA-Z_]+[a-zA-Z0-9_]+))
'@, [System.Text.RegularExpressions.RegexOptions]::Compiled + [System.Text.RegularExpressions.RegexOptions]::CultureInvariant + [System.Text.RegularExpressions.RegexOptions]::ExplicitCapture)

		function _expand_env_vars([string] $value, [ImportEnvValueType] $value_type) {
			function _expand_env_vars_core([string] $value) {
				# interpret ${VAR} and $VAR expressions as environment variables, instead of powershell variables
				for ($decent_level = 0; $decent_level -le 10; $decent_level++) {
					$match_collection = $expand_regex.Matches($value)
					foreach ($match in $match_collection) {
						$var = $match.Groups["var_box"].Value
						$var = if ($var) { $var } else { $match.Groups["var_literal"].Value }
						$var = _get_env_var $var
						$value = $value.Remove($match.Index, $match.Length).Insert($match.Index, $var)
					}
					if ($match_collection.Count -eq 0) {
						break
					}
					if ($decent_level -eq 10) {
						Write-Warning 'Expanding variable failed: Too many nested variable expressions. Using value as is.'
					}
				}
				return $value
			}

			if ($Expand -eq [ImportEnvExpand]::Never) {
				return $value
			}
			if ($value_type -ne [ImportEnvValueType]::Simple -and $value_type -ne [ImportEnvValueType]::Interpolated -and $Expand -ne [ImportEnvExpand]::Force) {
				return $value
			}

			$value = _expand_env_vars_core $value
			return $value
		}

		function _load_file([string] $file)	{
			# if file exists, load it
			if (-not (Test-Path $file)) {
				throw "Error loading file '$file': File not found"
			}
			$file_content = Get-Content $file -Raw -Encoding $Encoding
			# if the file is empty, return
			if ($file_content.Length -eq 0) {
				Write-Debug "File '$file' is empty"
			}
			return $file_content
		}

		$expr_regex = [System.Text.RegularExpressions.Regex]::new(@'
(?si)(?<key>[^\n\s#]*?)\s*=\s*(?:(?:"""(?<value_inter_multi>(.*(?=""")))""")|(?:"(?<value_inter>(?:[^\\"]|\\.)*?)")|(?:'''(?<value_literal_multi>(?:.*(?=''')))''')|(?:'(?<value_literal>(?:[^\\']|\\.)*?)')|(?<value_simple>[^"\n#]+)|(?<value_none>\s*\n))|(?<comment>\#[^\n]*)|(?<key_only>[^\n\s#]+)|(?<whitespace>\s+|\n+|$)
'@, [System.Text.RegularExpressions.RegexOptions]::Compiled + [System.Text.RegularExpressions.RegexOptions]::CultureInvariant + [System.Text.RegularExpressions.RegexOptions]::ExplicitCapture)

		function _parse_matches([string] $file_content) {

			# match the regex and convert the pattern to a array of key = value_multi | value_single
			$match_collection = $expr_regex.Matches($file_content)
			# validate that the entire file was matched
			if ($match_collection.Count -eq 0) {
				Write-Warning "The file did not match the parser"
			}
			$first_match = $match_collection[0]
			$last_match = $match_collection[$match_collection.Count - 1]
			if ($first_match.Index -ne 0 -or ($last_match.Index + $last_match.Length -ne $file_content.Length)) {
				throw "Error loading file: Invalid .env file format: Failed to parse the entire file"
			}
			# only return key-value pair matches, even if empty
			return $match_collection | Where-Object { $_ -and $_.Success -and ($_.Groups["key"].Success -or $_.Groups["key_only"].Success) }
		}

		$key_regex = [System.Text.RegularExpressions.Regex]::new(@'
^[a-zA-Z_]+[a-zA-Z0-9_]*$
'@, [System.Text.RegularExpressions.RegexOptions]::Compiled + [System.Text.RegularExpressions.RegexOptions]::CultureInvariant + [System.Text.RegularExpressions.RegexOptions]::ExplicitCapture)

		function _interpret_match([System.Text.RegularExpressions.Match] $match) {
			function _trim_newline([string] $value) {
					<#
					Trim the first and last newline character from a string.
				#>
					if ($value.EndsWith("`n")) {
						$value = $value.Substring(0, $value.Length - 1)
					}
					elseif ($value.EndsWith("`r`n")) {
						$value = $value.Substring(0, $value.Length - 2)
					}
					elseif ($value.EndsWith("`r")) {
						$value = $value.Substring(0, $value.Length - 1)
					}
					if ($value.StartsWith("`n")) {
						$value = $value.Substring(1)
					}
					elseif ($value.StartsWith("`r`n")) {
						$value = $value.Substring(2)
					}
					elseif ($value.StartsWith("`r")) {
						$value = $value.Substring(1)
					}
					return $value
				}
				function _interpret_match_core([string] $key, [string] $value, [ImportEnvValueType] $value_type) {
					# expand environment variables
					$value = _expand_env_vars $value $value_type
					# unescape the value
					$value = _unescape $value $value_type
					# return the key and value
					return [System.Collections.Generic.KeyValuePair[string, string]]::new($key, $value)
				}
				$match_span = "$($match.Index)..$($match.Index + $match.Length - 1)"

				$key = $match.Groups["key_only"].Value
				if ($key) {
					Write-Warning "Invalid variable format: Missing '=' sign after key '$key' at $match_span. Ignoring variable."
					return
				}

				$key = $match.Groups["key"].Value.Trim()
				if ($key.Length -eq 0) {
					Write-Warning "Invalid variable format: Hidden environment variables are not allowed: '=HIDDEN=VALUE'. Ignoring variable."
					return
				}
				# validate the key against [a-zA-Z_]+[a-zA-Z0-9_]*
				if ($key -notmatch $key_regex) {
					Write-Warning "Invalid variable format: Invalid key '$key' at $match_span. Ignoring variable."
					return
				}

				$value = $match.Groups["value_simple"].Value.Trim()
				if ($value) {
					# ensure the value does not start with ", because this is a missing terminating "
					if ($value.Contains('"') -or $value.Contains("'")) {
						Write-Warning "Invalid variable format: Quotation disallowed in simple expressions at $match_span. Using the value as-is."
					}
					$value = $value.TrimEnd()
					return _interpret_match_core $key $value Simple
				}

				# handle interpolated values
				$value = $match.Groups["value_inter"].Value
				$value = if ($value) { $value } else { _trim_newline $match.Groups["value_inter_multi"].Value }
				if ($value) {
					return _interpret_match_core $key $value Interpolated
				}

				#handle literal values
				$value = $match.Groups["value_literal"].Value
				$value = if ($value) { $value } else { _trim_newline $match.Groups["value_literal_multi"].Value }
				if ($value) {
					return _interpret_match_core $key $value Literal
				}

				return [System.Collections.Generic.KeyValuePair[string, string]]::new($key, '')
			}
			function _parse_file_content([string] $file_content) {
				$match_collection = _parse_matches $file_content

				$failure_count = 0
				$match_collection | ForEach-Object {
					$key_value_pair = _interpret_match $_
					if (-not $key_value_pair) {
					$failure_count += 1
				}
				else {
					$variables[$key_value_pair.Key] = $key_value_pair.Value
				}
			}

			if ($failure_count -gt 0) {
				Write-Warning "Invalid .env file format: $($match_collection.Count - $failure_count) lines loaded, $failure_count lines failed. See warnings for details."
			}
		}
	}

	process {
		##
		# Main Logic
		##
		if (-not $File) {
			Write-Debug 'File parameter is empty'
			return
		}
		if ($Raw) {
			if ($File.Length -ne 1) {
				Write-Warning 'To support multiline values Raw mode requires the content to be passed as a single [string] into the -File parameter'
			}
			foreach ($file in $File) {
				try {
					_parse_file_content $file
					$success_count += 1
				}
				catch {
					# write the exception to the console
					$file = "InputStream@$($file.Length)"
					Write-Warning "Failed to proccess the file '$file': $_"
					$failures += $file
				}
			}
		}
		else {
			# load each file in the array
			foreach ($file in $File) {
				try {
					$file_content = _load_file $file
					if ($file_content) {
						_parse_file_content $file_content
					}
					$success_count += 1
				}
				catch {
					# write the exception to the console
					Write-Warning "Failed to proccess the file '$file': $_"
					$failures += $file
				}
			}
		}
	}

	end {
		# output variables
		$variables

		$failure_count = $failures.Count
		$total_count = $failure_count + $success_count
		# if filename is not specified, use local .env
		if ($total_count -eq 0) {
			Write-Debug 'No files loaded'
		}

		Write-Debug "Import-Env : Sucessfully loaded $success_count files"
		if ($failure_count -gt 0) {
			Write-Error "Failed to load $failure_count out of $total_count files: $failures"
		}
	}
}

enum ExportEnvTarget {
	Process
	User
	Machine
	Pipe
}

function Export-Env {
	<#
	.SYNOPSIS
	Export the key-value pairs from memory to the specified target

	.DESCRIPTION
	The key-value pairs are exported to the specified target. For environment variables that can be the scopes process, user, or machine.
	For the pipe target, the key-value pairs are piped to the next command using the Success (1) stream.

	.PARAMETER Variables
	An array of [System.Collections.Generic.KeyValuePair[string, string]] variables to export

	.PARAMETER Target
	The target to export the environment variables to
	If not specified, the default is 'Process'
	Variables will always be read from the process scope, regardless of the scope specified

	Targets:
	- Process enviroment variables the current process, and any child processes
	- User enviroment variablesis only available on Windows
	- Machine enviroment variables require elevated privileges
	- Pipe does not set the environment variables, but instead pipes them to the next command using the Success (1) stream.

	.INPUTS
	[System.Collections.Generic.KeyValuePair[string, string]] Variables same as the output of Import-Env

	.OUTPUTS
	The success stream (1) is reserved for pipeline output, and will be used to pipe the environment variables to the next command.
	If the target is not 'Pipe', the output will be empty.
	The content is a stream of [string] key-value pairs in the format key="value" with the value normalized to a single line by escaping offending characters.

	.LINK
	The specification of the .env format can be found at https://hexdocs.pm/dotenvy/dotenv-file-format.html

	.EXAMPLE
	Get-Item '.env' | Import-Env | Export-Env -Target Pipe 1> tmp.env
	Imports the file '.env' and stores the environment variables in the file 'tmp.env'

	.EXAMPLE
	Import-Env .env,.env_test | Export-Env
	Imports the files '.env' and '.env_test' to the process scope

	.EXAMPLE
	.env,.env.test | Import-Env | Export-Env
	Imports the variables of the files '.env' and '.env.test' to the process scope

	.EXAMPLE
	Import-Env .env | Export-Env -Target User
	Imports the file '.env' into the user scope

	.EXAMPLE
	Import-Env $HOME/.env | Export-Env -Target Pipe 1> .env
	Imports the file '~/.env' and stores the environment variables in the file '.env'
	#>
	[OutputType([string[]])]
	param(
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)][Alias('v')]
		[System.Collections.Generic.Dictionary[string, string]] $Variables,
		[Parameter(Mandatory = $false)][Alias('t')]
		[ExportEnvTarget] $Target = [ExportEnvTarget]::Process
	)
	begin {
		$success_count = 0
		$failures = @()

		##
		# Helper functions
		##
		function _escape([string] $value) {
			# escape any non-controlsequence character with a backslash
			$sb = [System.Text.StringBuilder]::new()
			for ([int] $pos = 0; $pos -lt $value.Length; $pos += 1) {
				[char] $char = $value[$pos]
				switch ($char) {
					'\' { [void]$sb.Append('\\') }
					'$' { [void]$sb.Append('\$') }
					'"' { [void]$sb.Append('\"') }
					'' { [void]$sb.Append('\a') }
					'' { [void]$sb.Append('\b') }
					'' { [void]$sb.Append('\f') }
					"`n" { [void]$sb.Append('\n') }
					"`r" { [void]$sb.Append('\r') }
					"`t" { [void]$sb.Append('\t') }
					'' { [void]$sb.Append('\v') }
					default { [void]$sb.Append($char) }
				}
			}
			return $sb.ToString()
		}

		function _set_env_var([string] $name, [string] $value) {
			if ($Target -eq [ExportEnvTarget]::Pipe) {
				# pipe the environment variable to the next command
				$value = _escape $value
				Write-Output -InputObject "$name=`"$value`""
			}
			elseif ($Target -eq [ExportEnvTarget]::Process) {
				# thrid parameter is a unavailable on Linux
				[System.Environment]::SetEnvironmentVariable($name, $value)
			}
			else {
				$target = switch ($Target) {
					[ExportEnvTarget]::Machine { [System.EnvironmentVariableTarget]::Machine }
					[ExportEnvTarget]::User { [System.EnvironmentVariableTarget]::User }
				}
				[System.Environment]::SetEnvironmentVariable($name, $value, $target)
			}
		}
	}

	process {
		##
		# Main Logic
		##
		foreach ($key_value_pair in $Variables.GetEnumerator()) {
			[string] $name = $key_value_pair.Key
			[string] $value = $key_value_pair.Value

			try {
				_set_env_var $name $value
				$success_count += 1
			}
			catch {
				Write-Warning "Failed to assign variable '$name' to target '$Target': $_"
				$failures += $name
			}
		}
	}

	end {
		$failure_count = $failures.Count
		$total_count = $failure_count + $success_count
		if ($total_count -eq 0) {
			Write-Debug "No variables exported"
		}

		Write-Debug "Export-Env : Sucessfully exported $success_count variables"
		if ($failure_count -gt 0) {
			throw "Failed to export $failure_count out of $total_count variables: $failures"
		}
	}
}

function Use-Env {
	<#
	.SYNOPSIS
	Executes a command with the specified environment variables

	.DESCRIPTION
	Ensures that the current environment variables are restored after the command is executed, even if the command fails

	.PARAMETER Variables
	A dictionary of environment variables to use

	.PARAMETER Command
	The command string to execute
	Invoked using Invoke-Expression without any alterations

	.INPUTS
	[System.Collections.Generic.KeyValuePair[string, string]] Variables same as the output of Import-Env

	.NOTES

	.EXAMPLE
	# ensure the value is $null
	$env:DoubleQuoteMultiline=$null
	# use env to store the value into $test
	$test=Import-Env .env | Use-Env '$env:DoubleQuoteMultiline'
	# check that the variable is set
	$test
	> asdasd
	> asdasd # Not A Comment
	> asdasd
	> Line"
	> StringValue
	# check that the environment variable is not set
	$env:DoubleQuoteMultiline
	>
	#>
	param(
		[Parameter(Mandatory = $false, ValueFromPipeline = $true)][Alias('v')]
		[System.Collections.Generic.Dictionary[string, string]] $Variables,
		[Parameter(Mandatory = $true, Position = 0)][Alias('c')]
		$Command
	)

	# the current environment variables
	[System.Collections.Generic.Dictionary[string, string]] $current_vars = Import-Env -IncludeSystemVariables
	# merge with the specified variables
	[System.Collections.Generic.Dictionary[string, string]] $target_vars = [System.Collections.Generic.Dictionary[string, string]]::new($current_vars, (Get-OsSensitiveStringComparer))
	foreach ($key_value_pair in $Variables.GetEnumerator()) {
		if ($key_value_pair.Key) {
			$target_vars[$key_value_pair.Key] = if ($key_value_pair.Value) { $key_value_pair.Value } else { $null }
		}
		# ensure that the variable is reset by adding it [key]=$null to current_vars, if not already defined
		if (-not $current_vars.ContainsKey($key_value_pair.Key)) {
			$current_vars[$key_value_pair.Key] = $null
		}
	}
	# export the variables
	$target_vars | Export-Env -Target Process
	Write-Debug "Use-Env : Executing the command with $($target_vars.Count) environment variables"
	# execute the command
	try {
		Invoke-Expression $Command
	}
	finally {
		# restore the environment variables
		$current_vars | Export-Env -Target Process
		Write-Debug "Use-Env : Restored $($current_vars.Count) environment variables"
	}
}

function dotenv {
	<#
	.SYNOPSIS
	dotenv-cli like tool

	.DESCRIPTION
	Internally uses the functions Import-Env, Export-Env, Use-Env to provide an interface simmilar to dotenv-cli

	.PARAMETER EnvFiles
	The env files to use

	.PARAMETER Configuration
	The env configuration to use

	.PARAMETER Variables
	The list of custom variables to use
	Overwrite the variables from the env files

	.PARAMETER Command
	The command to execute

	.EXAMPLE

	.NOTES
	Besides the shell induced differences to dotenv-cli, the following differences exist:
	- The precedence of environment variables is as follows: System > .env > .env.local > .env.[configuration] > -v Variable
	- The -o parameter is thus not supported
	- The -c parameter requires a value. pass the empty string for the local configuration only
	#>
	param(
		[Parameter(Mandatory = $false)][Alias('e')]
		[string[]] $EnvFiles,
		[Parameter(Mandatory = $false)][Alias('c')]
		[AllowNull()] $Configuration = $null,
		[Parameter(Mandatory = $false)][Alias('v')]
		[string[]] $Variables,
		[Parameter(Mandatory = $false)][Alias('p')]
		[string[]] $Probes,
		[Parameter(Mandatory = $false, Position = 0)]
		[string] $Command
	)

	function _merge_var([System.Collections.Generic.Dictionary[string, string]] $lhs, [string] $key, [string] $value) {
		if ($key) {
			$lhs[$key] = if ($value) { $value } else { $null }
		}
	}

	function _add_configuration($env_files, $config) {
		# reverse loop to ensure that the last configuration is the first in the list
		for ($i = $env_files.Count - 1; $i -ge 0; $i--) {
			$env_file = "$($env_files[$i]).$config"
			if (Test-Path $env_file) {
				$env_files += $env_file
			}
		}
		$env_files
	}

	# if no env files are specified, use the default .env
	if (-not $EnvFiles) {
		$EnvFiles = if (Test-Path '.env') { @('.env') } else { @() }
	}
	# append configuration specific env files
	if ($null -ne $Configuration) {
		$Configuration = [string]$Configuration
		if ($Configuration -ne '') {
			$EnvFiles = _add_configuration $EnvFiles $Configuration
		}
		$EnvFiles = _add_configuration $EnvFiles 'local'
	}
	# load the process environment
	[System.Collections.Generic.Dictionary[string, string]] $vars = Import-Env -IncludeSystemVariables
	# load the env files
	if ($EnvFiles) {
		($EnvFiles | Import-Env).GetEnumerator() | ForEach-Object { _merge_var $vars $_.Key $_.Value }
	}
	# load the custom variables
	if ($Variables) {
		($Variables | Import-Env -Raw).GetEnumerator() | ForEach-Object { _merge_var $vars $_.Key $_.Value }
	}

	if ($Probes) {
		# export the probe variables
		foreach ($probe in $Probes.GetEnumerator()) {
			if ($vars.ContainsKey($probe)) {
				Write-Output $vars[$probe]
			}
		}
	}

	if ($Command) {
		# execute the command
		$vars | Use-Env $Command
	}
}
