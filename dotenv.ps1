###############################################################################
# Self installation
###############################################################################
# Self installation Source https://github.com/jpassing/powershell-install-as-module/blob/master/Install-Template.ps1 licensed under APACHE 2.0
[CmdletBinding()]
Param(
	[Parameter(Mandatory = $false)][ValidateSet("LocalMachine", "CurrentUser")][string] $Install,
	[Parameter(Mandatory = $false)][ValidateSet("LocalMachine", "CurrentUser")][string] $Uninstall
)

###############################################################################
###= dotenv\dotenv.psd1
###############################################################################

@{
	ModuleVersion     = '0.1.0'
	RootModule        = 'dotenv.psm1'
	FunctionsToExport = @(
		'Import-Env',
		'Export-Env'
	)
}

###############################################################################
###=
###############################################################################

function Install-ScriptAsModule {
	<#
			.SYNOPSIS
					Generate a Powershell module from this script and install it.
	#>
	Param(
		[Parameter(Mandatory = $True)][string]$ModulePath,
		[Parameter(Mandatory = $false)][string]$Prefix = "###="
	)

	$OutputFile = $Null
	$FullOutputPath = $Null
	Get-Content $script:MyInvocation.MyCommand.Path | Foreach-Object {
		if ($_.StartsWith($Prefix)) {
			# Start a new file
			$OutputFile = $_.Substring($Prefix.Length).Trim()

			if ($OutputFile) {
				$FullOutputPath = (Join-Path -Path $ModulePath -ChildPath $OutputFile)

				New-Item `
					-ItemType Directory `
					-Force -Path ([System.IO.Path]::GetDirectoryName($FullOutputPath)) | Out-Null

				# Truncate file
				"" | Out-File  $FullOutputPath
			}
		}
		elseif ($OutputFile) {
			# Keep appending to file
			$_ | Out-File  $FullOutputPath -Append
		}
	}
}

function Uninstall-ScriptAsModule {
	<#
			.SYNOPSIS
					Renove Powershell module that has been generated from this script.
	#>
	Param(
		[Parameter(Mandatory = $True)][string]$ModulePath,
		[Parameter(Mandatory = $false)][string]$Prefix = "###="
	)

	Get-Content $script:MyInvocation.MyCommand.Path | Where-Object { $_.StartsWith($Prefix) } | Foreach-Object {
		$OutputFile = $_.Substring($Prefix.Length).Trim()

		if ($OutputFile) {
			$FullOutputPath = (Join-Path -Path $ModulePath -ChildPath $OutputFile)

			if (Test-Path $FullOutputPath) {
				Remove-Item -Force $FullOutputPath
			}
		}
	}
}

$_PowerShellModuleFolders = @{
	LocalMachine = (Join-Path -Path $Env:ProgramFiles -ChildPath "WindowsPowerShell\Modules\");
	CurrentUser  = (Join-Path -Path ([environment]::getfolderpath("mydocuments")) -ChildPath "WindowsPowerShell\Modules\")
}

Write-Host ""
Write-Host "Advanced functions added to current session."

if ($Uninstall) {
	Uninstall-ScriptAsModule -ModulePath $_PowerShellModuleFolders[$Uninstall]
	Write-Host "Advanced functions removed from $($_PowerShellModuleFolders[$Uninstall])"
}
elseif ($Install) {
	Install-ScriptAsModule -ModulePath $_PowerShellModuleFolders[$Install]
	Write-Host "Advanced functions installed to $($_PowerShellModuleFolders[$Install])"
}
else {
	Write-Host "Use -Install to add functions permanenently."
}

###############################################################################
###= dotenv\dotenv.psm1
###############################################################################

#Requires -version 4

Set-StrictMode -Version Latest

$ErrorActionPreference = 'Stop'

enum ImportEnvExpand {
	Default
	Force
	Never
}

function Import-Env {
	<#
	.SYNOPSIS
	Import environment variables from a .env file

	.DESCRIPTION
	Import environment variables from a .env file.
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

	.INPUTS
	The string[] of file names to import, same as the file_name parameter
	If Raw is set, the string content of the file(s) to import

	.OUTPUTS
	The success stream (1) is reserved for pipeline output, and will be used to pipe the environment variables to the next command
	The output is a stream of [System.Collections.Generic.KeyValuePair[string, string]] objects

	.LINK
	The specification of the .env format can be found at https://hexdocs.pm/dotenvy/dotenv-file-format.html

	.NOTES
	Values can be one of three types, denoted by the quotation marks
	- Unquoted values: Escape sequences are disabled, Expressions are enabled
	- Single quoted values: Escape sequences are disabled, Expressions are diseabled
	- Double quoted values: Escape sequences are enabled, Expressions are enabled
	Use three consecutive quotes for multiline values, the leading and trailing line breaks are removed. The settings of the quotes used are applied

	.EXAMPLE
	Import-Env .env | Export-Env
	Imports the file '.env' and exports the variables into the Process environment

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

	'''                   # Tailing line breaks are removed
	=HIDDEN=DISSALLOWED   # This is ignored
	AnotherVariable=Hello # This is a comment
  #>
	[OutputType([System.Collections.Generic.Dictionary[string, string]])]
	param (
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
		[string[]] $File,
		[Parameter(Mandatory = $false)]
		$Encoding = 'utf8',
		[Parameter(Mandatory = $false)]
		[switch] $Raw,
		[Parameter(Mandatory = $false)]
		[ImportEnvExpand] $Expand = [ImportEnvExpand]::Default
	)

	begin {
		$variables = [System.Collections.Generic.Dictionary[string, string]]::new()
		[int] $success_count = 0
		[string[]] $failures = @()
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
			if (!$name -or $name -eq '') {
				return ''
			}
			# attempt to get the value from the $variables
			$value = $variables[$name]
			if ($null -ne $value) {
				return $value
			}
			# attempt to get the environment variable
			$value = [System.Environment]::GetEnvironmentVariable($name, [System.EnvironmentVariableTarget]::Process)
			if ($value) {
				return $value
			}
			Write-Warning "Environment variable '$name' does not exist"
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
			if (!(Test-Path $file)) {
				throw "Error loading file '$file': File not found"
			}
			$file_content = Get-Content $file -Raw -Encoding $Encoding
			# if the file is empty, return
			if ($file_content.Length -eq 0) {
				Write-Warning "File '$file' is empty"
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
			if ($key -notmatch '^[a-zA-Z_]+[a-zA-Z0-9_]*$') {
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
				if (!$key_value_pair) {
					$failure_count += 1
				}
				else {
					$variables[$key_value_pair.Key] = $key_value_pair.Value
				}
			}

			if ($failure_count -gt 0) {
				Write-Error "Invalid .env file format: $($match_collection.Count - $failure_count) lines loaded, $failure_count lines failed. See above for details."
			}
		}
	}

	process {
		##
		# Main Logic
		##
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
					Write-Error "Failed to proccess the file '$file': $_"
					$failures += $file
				}
			}
		}
		else {
			# load each file in the array
			foreach ($file in $File) {
				try {
					$file_content = _load_file $file
					_parse_file_content $file_content
					$success_count += 1
				}
				catch {
					# write the exception to the console
					Write-Error "Failed to proccess the file '$file': $_"
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
			Write-Warning 'No files loaded'
		}

		Write-Host "Import-Env : Sucessfully loaded $success_count files" -ForegroundColor Green
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
	Exports the key-value pairs to environment variables

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
	Imports the file '.env'

	.EXAMPLE
	Import-Env .env,.env_test | Export-Env
	Imports the files '.env' and '.env_test' to the process scope

	.EXAMPLE
	@(.env,.env_test) | Import-Env | Export-Env
	Imports the variables of the files '.env' and '.env_test' to the process scope

	.EXAMPLE
	Import-Env .env | Export-Env -Target User
	Imports the file '.env' into the user scope

	.EXAMPLE
	Import-Env $HOME/.env | Export-Env -Target Pipe 1> .env
	Imports the file '~/.env' and stores the environment variables in the file '.env'
	#>
	[OutputType([string[]])]
	param(
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
		[System.Collections.Generic.Dictionary[string, string]] $Variables,
		[Parameter(Mandatory = $false)]
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
			else {
				$target = switch ($Target) {
					[ExportEnvTarget]::Machine { [System.EnvironmentVariableTarget]::Machine }
					[ExportEnvTarget]::User { [System.EnvironmentVariableTarget]::User }
					[ExportEnvTarget]::Process { [System.EnvironmentVariableTarget]::Process }
				}
				[System.Environment]::SetEnvironmentVariable($name, $value, $target)
			}
		}
	}

	process {
		##
		# Main Logic
		##
		foreach ($key_value_pair in $Variables) {
			[string] $name = $key_value_pair.Key
			[string] $value = $key_value_pair.Value

			try {
				_set_env_var $name $value
				$success_count += 1
			}
			catch {
				Write-Error "Failed to assing variable '$name' to target '$Target': $_"
				$failures += $name
			}
		}
	}

	end {
		$failure_count = $failures.Count
		$total_count = $failure_count + $success_count
		if ($total_count -eq 0) {
			Write-Warning "No variables exported"
		}

		Write-Host "Export-Env : Sucessfully exported $success_count variables" -ForegroundColor Green
		if ($failure_count -gt 0) {
			throw "Failed to export $failure_count out of $total_count variables: $failures"
		}
	}
}

function Get-Env {
	<#
	.SYNOPSIS
	Query variables from Import-Env in addition to the environment variables

	.DESCRIPTION
	Pass the output of Import-Env to Get-EnvVar to query the variables in addition to the environment variables

	.PARAMETER Variables
	The dictionary of key-value pairs representing the additional variables
	Used as stream input

	.PARAMETER Probe
	Function accepting the key [string] that determines [bool] whether the variable should be returned

	.INPUTS
	[System.Collections.Generic.Dictionary[string, string]] Variables same as the output of Import-Env but as a dictionary
	.OUTPUTS
	[System.Collections.Generic.Dictionary[string, string]] The filtered variables
	.LINK

	.NOTES

	.EXAMPLE

	#>
	[OutputType([System.Collections.Generic.Dictionary[string, string]])]
	param(
		[Parameter(Mandatory = $false, ValueFromPipeline = $true)]
		[System.Collections.Generic.Dictionary[string, string]] $Variables,
		[Parameter(Mandatory = $true, Position = 0)]
		[Func[string, bool]] $Probe
	)

	begin {
		$env_vars = [System.Collections.Generic.Dictionary[string, string]]::new()
	}

	process {
		foreach ($key_value_pair in $Variables) {
			[string] $name = $key_value_pair.Key
			[string] $value = $key_value_pair.Value

			if ($Probe.Invoke($name)) {
				$env_vars.Add($name, $value)
			}
		}
	}

	end {
		$env_vars
	}
}
