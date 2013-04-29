

$NewDir="pcbiq"
$ExportPath = "C:\temp\"

$DCServiceName = "SP2013-AIS-"+$NewDir+"-DC"
$SQLServiceName = "SP2013-AIS-"+$NewDir+"-SQL"
$SPSVR1ServiceName = "SP2013-AIS-"+$NewDir+"-SVR1"
$SPSVR2ServiceName = "SP2013-AIS-"+$NewDir+"-SVR2"


$VnetName= 'MyNetwork'

$path = $ExportPath +"SP2013DC1.xml"
$vm = Import-AzureVM -Path $path
New-AzureVM -ServiceName $DCServiceName -VMs $vm -VNetName $VNetName

$path = $ExportPath +"SP2013SQL1.xml"
$vm = Import-AzureVM -Path $path
New-AzureVM -ServiceName $SQLServiceName -VMs $vm -VNetName $VNetName

$path = $ExportPath +"SP2013SRV1.xml"
$vm = Import-AzureVM -Path $path
New-AzureVM -ServiceName $SPSVR1ServiceName -VMs $vm -VNetName $VNetName

$path = $ExportPath +"SP2013SRV2.xml"
$vm = Import-AzureVM -Path $path
New-AzureVM -ServiceName $SPSVR2ServiceName -VMs $vm -VNetName $VNetName

Restart-AzureVM -ServiceName $DCServiceName -Name "SP2013DC1"
Restart-AzureVM -ServiceName $SQLServiceName -Name "SP2013SQL1"
Restart-AzureVM -ServiceName $SPSVR1ServiceName -Name "SP2013SRV1"
Restart-AzureVM -ServiceName $SPSVR2ServiceName -Name "SP2013SRV2"



