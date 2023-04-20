BeforeAll {
  . $PSScriptRoot/dotenv.ps1
  $ErrorActionPreference = 'Continue'
  $WarningPreference = 'Continue'
  $DebugPreference = 'Continue'
}

Describe 'Import-Env' {
  It 'imports the environment variables from the .env file' {
    $vars = Import-Env '.\.env'
    $vars | Should -Not -BeNullOrEmpty
    $vars.GetEnumerator() | Should -HaveCount 10
    $keys = $vars.Keys
    $keys | Should -Contain 'Hello'
    $keys | Should -Contain 'Multi'
    $keys | Should -Contain 'WhiteSpace'
    $keys | Should -Contain 'DoubleQuote'
    $keys | Should -Contain 'DoubleQuoteMultiLine'
    $keys | Should -Contain 'Unicode'
    $keys | Should -Contain 'SingleQuote'
    $keys | Should -Contain 'SingleQuoteNoVar'
    $keys | Should -Contain 'PRIVATE_KEY'
  }

  It 'expands all variables when Expand Force is set' {
    $vars = Import-Env .\.env -Expand Force
    # check if the SingleQuoteNoVar variable was expanded from $Hello to ''
    $vars['SingleQuoteNoVar'] | Should -Be ''
  }

  It 'never expands variables when Expand Never is set' {
    $vars = Import-Env .\.env -Expand Never
    # check if the SingleQuoteNoVar variable was expanded from $Hello to ''
    $vars['SingleQuoteNoVar'] | Should -Be '$Hello'
    # check if DoubleQuote was expanded from ${Multi}Value to Line\"\nStringValue
    $vars['DoubleQuote'] | Should -Be '${Multi}Value'
  }
}

Describe 'Export-Env' {
  It 'allows a roundtrip' {
    $varsRef = Import-Env '.\.env'
    $varsRef | Should -Not -BeNullOrEmpty

    $vars = Import-Env .\.env | Export-Env -Target Pipe | Import-Env -Raw
    $vars | Should -Not -BeNullOrEmpty
    $vars | ConvertTo-Json | Should -Be ($varsRef | ConvertTo-Json)
  }

  It 'exports process environment variables' {
    # clear all relevant environment variables
    $vars = Import-Env '.\.env'
    $vars.GetEnumerator() | ForEach-Object { "`$env:$($_.Key)=''" | Invoke-Expression }
    # export to the current process
    $vars | Export-Env -Target Process
    # get the exported variables by the keys in vars and verify they are have the same value
    $vars.GetEnumerator() | ForEach-Object {
      $value = if ($_.Value) { $_.Value } else { $null }
      $value | Should -Be ("`$env:$($_.Key)" | Invoke-Expression)
    }
  }
}

Describe 'Use-Env' {
  It 'allows extraction of a environment variable' {
    # ensure the value is $null
    $env:DoubleQuoteMultiline = $null
    # use env to store the value into $test
    $test = Import-Env .env | Use-Env '$env:DoubleQuoteMultiline'
    # check that the variable is set
    $test | Should -Not -BeNullOrEmpty
    # check that the environment variable is not set
    $env:DoubleQuoteMultiline | Should -BeNullOrEmpty
  }
}

Describe 'dotenv' {
  It 'allows probing values' {
    [string[]]$query = dotenv -e .env -p DoubleQuoteMultiline, DoubleQuote
    $query.Count | Should -Be 2
    $query[0] | Should -Not -BeNullOrEmpty
    $query[1] | Should -Be "Line`"`nStringValue"
  }

  It 'returns null when probing non existing values' {
    dotenv -e .env -p DoesNotExist | Should -BeNullOrEmpty
  }

  It 'executes commands' {
    $test = dotenv -e .env 'echo $env:DoubleQuote'
    $test | Should -Not -BeNullOrEmpty
    $test | Should -Be "Line`"`nStringValue"
  }

  It 'overrides .env values with .env.local configuration' {
    $test = dotenv -e .env 'echo $env:Hello'
    $test | Should -BeNullOrEmpty
    $test = dotenv -e .env -c '' 'echo $env:Hello'
    $test | Should -Not -BeNullOrEmpty
    $test | Should -Be "World"
  }

  It 'exports variables to the process if no command is provided' {
    dotenv -e .env -c ''
    $env:Hello | Should -Be "World"
  }
}
