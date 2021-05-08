function Invoke-MessageBox(){
    # Create dynamic assembly
    $DynamicAssembly = New-Object System.Reflection.AssemblyName("WinApiFuncs")
    $DynamicAssemblyBuilder = [System.Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly($DynamicAssembly,[System.Reflection.Emit.AssemblyBuilderAccess]::Run)

    # Create module in dynamic assembly
    $DynamicModuleBuilder = $DynamicAssemblyBuilder.DefineDynamicModule("WinApiFuncs")
    
    # Create type in module    
    $DynamicTypeBuilder = $DynamicModuleBuilder.DefineType("WinApiFuncs","Public, Class")

    # Create method in type
    $MessageBoxMethodBuilder = $DynamicTypeBuilder.DefinePInvokeMethod("MessageBox","user32.dll","Static, Public","Standard",[Int32],@([Int32],[string],[string],[Int32]),"Winapi","Auto")
    $WinApiInvokerType = $DynamicTypeBuilder.CreateType()
    
    $WinApiInvokerType::MessageBox($null,"BODY","TITLE",0)
}

Invoke-MessageBox