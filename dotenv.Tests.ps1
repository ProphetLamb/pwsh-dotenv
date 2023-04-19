BeforeAll {
  . $PSScriptRoot/dotenv.ps1
  function ConvertTo-HashTable($key_value_pairs) {
    $hash = @{}
    $key_value_pairs | ForEach-Object {
      $hash[$_.Key] = if ($_.Value) { $_.Value } else { $null }
    }
    return $hash
  }
  $ErrorActionPreference = 'Continue'
  $WarningPreference = 'Continue'
}

Describe 'Import-Env' {
  It 'should import the environment variables from the .env file' {
    $vars = Import-Env '.\.env'
    $vars | Should -Not -BeNullOrEmpty
    $vars | Should -HaveCount 11
    $keys = $vars.Key
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

  It 'should expand all variables when Expand Force is set' {
    $vars = Import-Env .\.env -Expand Force
    # convert vars to a hashtable
    $vars = ConvertTo-HashTable $vars
    # check if the SingleQuoteNoVar variable was expanded from $Hello to ''
    $vars['SingleQuoteNoVar'] | Should -Be $null
  }

  It 'should never expand variables when Expand Never is set' {
    $vars = Import-Env .\.env -Expand Never
    # convert vars to a hashtable
    $vars = ConvertTo-HashTable $vars
    # check if the SingleQuoteNoVar variable was expanded from $Hello to ''
    $vars['SingleQuoteNoVar'] | Should -Be '$Hello'
    # check if DoubleQuote was expanded from ${Multi}Value to Line\"\nStringValue
    $vars['DoubleQuote'] | Should -Be '${Multi}Value'
  }
}

Describe 'Export-Env' {
  It 'should allow a roundtrip' {
    $varsRef = Import-Env '.\.env'
    $varsRef | Should -Not -BeNullOrEmpty

    $vars = Import-Env .\.env | Export-Env -Target Pipe | Import-Env -Raw
    $vars | Should -Not -BeNullOrEmpty
    $vars | ConvertTo-Json | Should -Be ($varsRef | ConvertTo-Json)
  }

  It 'should export process environment variables' {
    # clear all relevant environment variables
    $vars = Import-Env '.\.env'
    $vars | ForEach-Object { "`$env:$($_.Key)=''" | Invoke-Expression }
    # export to the current process
    $vars | Export-Env -Target Process -Debug
    # convert vars to a hashtable
    $vars = ConvertTo-HashTable $vars
    # get the exported variables by the keys in vars and verify they are have the same value
    $vars.GetEnumerator() | ForEach-Object {
      $_.Value | Should -Be ("`$env:$($_.Key)" | Invoke-Expression)
    }
  }
}

Describe 'Use-Env' {
  It 'should allow extraction of a environment variable' {
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
  It 'should allow probing values' {
    [string[]]$query = dotenv -e .env -p DoubleQuoteMultiline, DoubleQuote
    $query.Count | Should -Be 2
    $query[0] | Should -Not -BeNullOrEmpty
    $query[1] | Should -Be "Line`"`nStringValue"
  }

  It 'should not return when probing non existing values' {
    dotenv -e .env -p DoesNotExist | Should -BeNullOrEmpty
  }

  It 'should execute commands' {
    $test = dotenv -e .env 'echo $env:DoubleQuote'
    $test | Should -Not -BeNullOrEmpty
    $test | Should -Be "Line`"`nStringValue"
  }

  It 'should override .env values with .env.local configuration' {
    $test = dotenv -e .env 'echo $env:Hello'
    $test | Should -BeNullOrEmpty
    $test = dotenv -e .env -c '' 'echo $env:Hello'
    $test | Should -Not -BeNullOrEmpty
    $test | Should -Be "World"
  }
}
