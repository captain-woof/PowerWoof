function Invoke-XorEncrypt{
    <#
    .SYNOPSIS
        Xor-encrypts any file or a text (provided as argument on command line) with any chosen key
    .PARAMETER TextToEncrypt
        A string to encrypt
    .PARAMETER FileToEncrypt
        A file to encrypt
    .PARAMETER Key
        The key to use to encrypt the text/file
    .PARAMETER Output
        Output file to save the encrypted data in
    .PARAMETER SuppressScreenOutput
        Supress the printing of encrypted data on screen
    .EXAMPLE
        Invoke-XorEncrypt -FileToEncrypt image.jpg -Key password123 -Output image.enc
        Xor-encrypts a file (image.jpg) using the key "password123" and saves it in 'image.enc'
    .EXAMPLE
        Invoke-XorEncrypt -TextToEncrypt "sample string here" -Key password123
        Xor-encrypts the text "sample text here" using the key "password123" and displays it.
    .INPUTS
        String
    #>

    [CmdletBinding()]
    param (
        [string] $TextToEncrypt,
        [string] $FileToEncrypt,
        [Parameter(Mandatory)] [string] $Key,
        [string] $Output,
        [switch] $SuppressScreenOutput
    )

    if(($PSBoundParameters.ContainsKey("TextToEncrypt")) -and !($PSBoundParameters.ContainsKey("FileToEncrypt"))){
        $ByteArrayToEncrypt = [System.Text.Encoding]::UTF8.GetBytes($TextToEncrypt)
    }elseif (($PSBoundParameters.ContainsKey("FileToEncrypt")) -and !($PSBoundParameters.ContainsKey("TextToEncrypt"))) {
        $ByteArrayToEncrypt = [System.IO.File]::ReadAllBytes($FileToEncrypt)
    }elseif(($PSBoundParameters.ContainsKey("FileToEncrypt")) -and ($PSBoundParameters.ContainsKey("TextToEncrypt"))){
        Write-Error "[!] Cannot process both a file and an input text"
        Exit-PSHostProcess
    }
    $ByteKey = [System.Text.Encoding]::ASCII.GetBytes($Key)    
    $EncryptedByteArray = New-Object byte[] $ByteArrayToEncrypt.Length

    Write-Host "Encrypting..."
    for($i=0; $i -lt $ByteArrayToEncrypt.Length; $i++){
        $EncryptedByteArray[$i] = $ByteKey[$i % $ByteKey.Length] -bxor $ByteArrayToEncrypt[$i]
    }
    if($PSBoundParameters.ContainsKey("Output")){
        [System.IO.File]::WriteAllBytes($Output,$EncryptedByteArray)
        $SizeWritten = $EncryptedByteArray.Length
        Write-Host "Written $SizeWritten bytes encrypted data to '$Output'"
    }
    Write-Host "Encrypted with chosen key '$Key'"
    if(!($PSBoundParameters.ContainsKey("SuppressScreenOutput"))){
        $ResultToDisplay = [System.Text.Encoding]::UTF8.GetString($EncryptedByteArray)
        Write-Host "Encrypted data: $ResultToDisplay"
    }
}

function Invoke-XorDecrypt{
    <#
    .SYNOPSIS
        Xor-decrypts any file or a text (provided as argument on command line) with any chosen key
    .PARAMETER TextToDecrypt
        A string to decrypt
    .PARAMETER FileToDecrypt
        A file to decrypt
    .PARAMETER Key
        The key to use to decrypt the text/file
    .PARAMETER Output
        Output file to save the decrypted data in
    .PARAMETER SuppressScreenOutput
        Supress the printing of decrypted data on screen
    .EXAMPLE
        Invoke-XorDecrypt -FileToDecrypt image.enc -Key password123 -Output image.jpg
        Xor-decrypts a file (image.enc) using the key "password123" and saves it in 'image.jpg'
    .EXAMPLE
        Invoke-XorDecrypt -TextToDecrypt "jaAJAHjCBcjSJWIE" -Key password123
        Xor-decrypts the text "jaAJAHjCBcjSJWIE" using the key "password123" and displays it.
    .INPUTS
        String
    #>

    [CmdletBinding()]
    param (
        [string] $TextToDecrypt,
        [string] $FileToDecrypt,
        [Parameter(Mandatory)] [string] $Key,
        [string] $Output,
        [switch] $SuppressScreenOutput
    )

    if(($PSBoundParameters.ContainsKey("TextToDecrypt")) -and !($PSBoundParameters.ContainsKey("FileToDecrypt"))){
        $ByteArrayToDecrypt = [System.Text.Encoding]::UTF8.GetBytes($TextToDecrypt)
    }elseif (($PSBoundParameters.ContainsKey("FileToDecrypt")) -and !($PSBoundParameters.ContainsKey("TextToDecrypt"))) {
        $ByteArrayToDecrypt = [System.IO.File]::ReadAllBytes($FileToDecrypt)
    }elseif(($PSBoundParameters.ContainsKey("FileToDecrypt")) -and ($PSBoundParameters.ContainsKey("TextToDecrypt"))){
        Write-Error "[!] Cannot process both a file and an input text"
        Exit-PSHostProcess
    }
    $ByteKey = [System.Text.Encoding]::ASCII.GetBytes($Key)    
    $DecryptedByteArray = New-Object byte[] $ByteArrayToDecrypt.Length

    Write-Host "Decrypting..."
    for($i=0; $i -lt $ByteArrayToDecrypt.Length; $i++){
        $DecryptedByteArray[$i] = $ByteKey[$i % $ByteKey.Length] -bxor $ByteArrayToDecrypt[$i]
    }

    if($PSBoundParameters.ContainsKey("Output")){
        [System.IO.File]::WriteAllBytes($Output,$DecryptedByteArray)
        $SizeWritten = $DecryptedByteArray.Length
        Write-Host "Written $SizeWritten bytes decrypted data to '$Output'"
    }
    Write-Host "Decrypted with chosen key '$Key'"
    if(!($PSBoundParameters.ContainsKey("SuppressScreenOutput"))){
        $ResultToDisplay = [System.Text.Encoding]::UTF8.GetString($DecryptedByteArray)
        Write-Host "Decrypted data: $ResultToDisplay"
    }
}