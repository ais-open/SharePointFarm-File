

 $NewDir="pcbiq"
 $ExportPath = "C:\temp\"
 
 $DCServiceName = "SP2013-AIS-"+$NewDir+"-DC"
    $SQLServiceName = "SP2013-AIS-"+$NewDir+"-SQL"
    $SPSVR1ServiceName = "SP2013-AIS-"+$NewDir+"-SVR1"
    $SPSVR2ServiceName = "SP2013-AIS-"+$NewDir+"-SVR2"

$serverArray = @($DCServiceName,$SQLServiceName,$SPSVR1ServiceName,$SPSVR2ServiceName)


foreach ($serviceName in $serverArray)
	{
Get-AzureVM -ServiceName $serviceName | foreach {
    $path = $ExportPath + $_.Name + '.xml'
    Export-AzureVM -ServiceName $serviceName -Name $_.Name -Path $path
}
# Faster way of removing all VMs while keeping the cloud service/DNS name

Remove-AzureDeployment -ServiceName $serviceName -Slot Production -Force
}
