function Find-Func {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $FuncName
    )
    Write-Host "Finding '$FuncName'"
    $Assemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()
    foreach($Assembly in $Assemblies){
        $Types = $Assembly.GetTypes()
        foreach($Type in $Types){
            $Methods = $Type.GetMethods()
            foreach ($Method in $Methods) {
                if($Method.Name -eq $FuncName -and $Method.IsStatic -eq $true){
                    Write-Host "Found '$FuncName'"
                    return $Method
                }
            }
        }
    }
    return $null
}

Write-Host "Finding necessary WinApi functions"
$GetModuleHandleMethod = Find-Func -FuncName "GetModuleHandle"
$GetProcAddressMethod = Find-Func -FuncName "GetProcAddress"

if($null -eq $GetModuleHandleMethod -or $null -eq $GetProcAddressMethod){
    Write-Warning -Message "Could not locate required WinApi methods"
    return
}else{
    Write-Host "Locating 'user32.dll'"
    $User32Dll = $GetModuleHandleMethod.Invoke($null,@("user32.dll"))
    if($User32Dll -eq 0){
        Write-Warning "Could not locate 'user32.dll"
        return
    }else{
        Write-Host "Located 'user32.dll'"
        Write-Host "Locating method 'MessageBoxA"
        $MessageBoxAFuncAddr = $GetProcAddressMethod.Invoke($null,@($User32Dll,"MessageBoxA"))
        if($MessageBoxAFuncAddr -eq 0){
            Write-Warning "Could not locate 'MessageBoxA'"
            return
        }else{
            # Create dynamic assembly for delegate
            $DynamicAssemblyNameForDelegate = New-Object System.Reflection.AssemblyName
            $DynamicAssemblyNameForDelegate.Name = "DynamicAssemblyDelegate"
            $DynamicAssemblyBuilderForDelegate = [System.Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly($DynamicAssemblyNameForDelegate,[System.Reflection.Emit.AssemblyBuilderAccess]::Run)
            $DynamicModuleBuilderForDelegate = $DynamicAssemblyBuilderForDelegate.DefineDynamicModule("DynamicModuleDelegate")
            $DynamicTypeBuilderDelegate = $DynamicModuleBuilderForDelegate.DefineType("MessageBoxA",'Public, Sealed',[System.MulticastDelegate])
               
            # Define the delegate
            $DynamicConstructorBuilderDelegate = $DynamicTypeBuilderDelegate.DefineConstructor("Public",[System.Reflection.CallingConventions]::Standard,@([Int32],[string],[string],[Int32]))
            $DynamicConstructorBuilderDelegate.SetImplementationFlags("Runtime")
            $DynamicDelegateMethodBuilder = $DynamicTypeBuilderDelegate.DefineMethod("Invoke","Public",[Int32],@([Int32],[string],[string],[Int32]))
            $DynamicDelegateMethodBuilder.SetImplementationFlags("Runtime")
            $CustomDelegateType = $DynamicTypeBuilderDelegate.CreateType()

            # Call 'MessageBoxA' now
            $CustomDelegate = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($MessageBoxAFuncAddr,$CustomDelegateType)
            $CustomDelegate.Invoke(0,"BODY","TITLE",0)
        }
    }
}