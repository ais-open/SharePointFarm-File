#AIS SharePoint deployment Scripts
#####################################################################
# Waits for system to restart,
#check if the machine is started by trying to get the machine name
#retry count is 60 -- 15 minutes 
#####################################################################
workflow WaitFor-SysRestart ($connectionUri, $cred)
{         
    $remComputerName="Notupdated"
    "Waiting for  $connectionUri"
  	$retries = 60
	while($remComputerName -eq "Notupdated" -and $retries -gt 0) 
	{
		try
		{
			$a=InlineScript
			{
				get-content env:computername 
			}  -PSConnectionUri $connectionUri -PSCredential $cred 
			$remComputerName=$a
             "Remote machine started name:" +$a + " Cloud service Uri :"+$connectionUri
		}
		catch [System.Exception]
		{
            inlineScript
            {
                Get-Date -Format "MMMM dd yyyy HH:mm:ss tt" 
            }
    		"Waiting for machine to boot.... Cloud service Uri :" + $connectionUri 
			Start-Sleep -Seconds 15
			$retries = $retries - 1			
		}
	}
	if($retries -eq 0)
	{
    	"Give up...Could not connect to machine at $cloudSvcName at port $port after multiple tries.."
		exit 
	}
  }

#####################################################################
# Restarts the provided VM
#####################################################################
workflow Restart-VM ($connectionUri, $cred)
{
    try
    {   
        "Restarting Machine $connectionUri" 
        InlineScript
        {            
           Restart-Computer -Force
        } -PSConnectionUri $connectionUri -PSCredential $cred 
     }
     catch [System.Exception]
     {
        "Restarting Machine $connectionUri  failed..." 
     }   
}

####################################################################
# Installs Active Directory on the machine, promotes as DNS server
# Add SharePoint service accounts and users
# Safe mode admin password is hardcoded to "Password1"
#####################################################################
workflow InstallAD($connectionUri, $cred)
{
    WaitFor-SysRestart -connectionUri $connectionUri -cred $cred
  
	#region Install Remote tools to install AD
    "Installing remote managemnet tools on the AD machine $cloudSvcName"
	InlineScript
	{
		#New-Item $featureLogPath -ItemType file -Force 
		$addsTools = "RSAT-AD-Tools" 
		Add-WindowsFeature $addsTools        
	}  -PSConnectionUri $connectionUri -PSCredential $cred 
    "Installing remote managemnet tools on the AD machine complete $cloudSvcName"
    #endregion Install Remote tools to install AD
   
    Restart-VM   -connectionUri $connectionUri -cred $cred 
    Start-Sleep -Seconds 15
    WaitFor-SysRestart -connectionUri $connectionUri -cred $cred
    Start-Sleep -Seconds 45
    
    #region install AD features
    "Installing active directory $connectionUri"	
    try
    {
	    InlineScript
	    {
            import-module servermanager
		    start-job -Name addFeature -ScriptBlock {                 
			    Add-WindowsFeature -Name "ad-domain-services" -IncludeAllSubFeature -IncludeManagementTools 
			    Add-WindowsFeature -Name "dns" -IncludeAllSubFeature -IncludeManagementTools 
			    Add-WindowsFeature -Name "gpmc" -IncludeAllSubFeature -IncludeManagementTools } 
		    Wait-Job -Name addFeature 
    	}  -PSConnectionUri $connectionUri  -PSCredential $cred 

    }
    catch [System.Exception]
    {
		"Installing active directory Failed $connectionUri"
    }
    "Installing active directory complete $connectionUri"

     #endregion install AD features

    Start-Sleep -Seconds 240
    Restart-VM   -connectionUri $connectionUri -cred $cred
    Start-Sleep -Seconds 15
    WaitFor-SysRestart  -connectionUri $connectionUri -cred $cred
    Start-Sleep -Seconds 180
    
    "Installing AD Forest $connectionUri"
    #region install AD Forest  
    try
    {
	    InlineScript
	    {
          # Create New Forest, add Domain Controller 
		  $domainname = "corp.ais.com" 
		  $netbiosName = "CorpAIS" 
		  import-module servermanager    
          Import-Module ADDSDeployment 
		  Install-ADDSForest -CreateDnsDelegation:$false  -DatabasePath "C:\Windows\NTDS"  -DomainMode "Win2012"  -DomainName $domainname  -DomainNetbiosName $netbiosName  -ForestMode "Win2012"  -InstallDns:$true  -LogPath "C:\Windows\NTDS"  -NoRebootOnCompletion:$false  -SysvolPath "C:\Windows\SYSVOL"  -Force:$true -SafeModeAdministratorPassword (ConvertTo-SecureString -AsPlainText -String "Password1" -Force)          

	    }  -PSConnectionUri $connectionUri  -PSCredential $cred 
    }
    catch [System.Exception]
    {
		"Installing active Forest Failed $connectionUri"
    }
    #endregion install AD Forest

	"Installing AD Forest complete $connectionUri"
    
	Start-Sleep -Seconds 240
    Restart-VM   -connectionUri $connectionUri -cred $cred 
    Start-Sleep -Seconds 45
    WaitFor-SysRestart  -connectionUri $connectionUri -cred $cred 
    #need more time as it would fail with an error# Attempting to perform the InitializeDefaultDrives operation on the 'ActiveDirectory' provider failed.
    Start-Sleep -Seconds 240
    
    #region add AD service accounts and users
    "Adding active directory users $connectionUri"
    try
    {
	    InlineScript
		{
			Import-Module ActiveDirectory  
			function createUser 
			{    
				param ([string] $ou, [string] $firstName, [string] $lastName, [string] $password, [string] $emailDomain)     
				$userName = $firstName + "." + $lastName    
				$fullName = $firstName + " " + $lastName   
				$emailAddress = $username + "@" + $emailDomain   
				New-ADUser -SamAccountName $userName -Name $fullName -DisplayName $fullName -GivenName $firstName -Surname $lastName -Path $ou -ChangePasswordAtLogon $false -AccountPassword (ConvertTo-SecureString -AsPlainText -String $password -Force) -Description $fullName -Enabled $true -EmailAddress $emailAddress -PasswordNeverExpires $true -UserPrincipalName $emailAddress 
			}  
			function createServiceUser 
			{  
				param ([string] $ou, [string] $userName, [string] $password, [string] $emailDomain)     
				$emailAddress = $username + "@" + $emailDomain     
				New-ADUser -SamAccountName $userName -Name $userName -DisplayName $fullName -Path $ou -ChangePasswordAtLogon $false -AccountPassword (ConvertTo-SecureString -AsPlainText -String $password -Force) -Description $userName -Enabled $true -EmailAddress $emailAddress -PasswordNeverExpires $true -UserPrincipalName $emailAddres
			}  

			$domain = [ADSI] "LDAP://dc=corp, dc=ais,dc=com"  
			$ouServices = $domain.Create("OrganizationalUnit", "OU=Services")
			$ouServices.SetInfo()  
			$ouUserProfiles = $domain.Create("organizationalUnit", "ou=SharePoint Users") 
			$ouUserProfiles.SetInfo()  
	 
			$ouUserProfilesEmployees = $ouUserProfiles.Create("organizationalUnit", "ou=Employees")
			$ouUserProfilesEmployees.SetInfo()  
			$services = [ADSI] "LDAP://ou=Services,dc=corp,dc=ais,dc=com"
			$employees = [ADSI] "LDAP://ou=Employees,ou=SharePoint Users,dc=corp,dc=ais,dc=com"  
			$dummyPassword = "Passw0rd" #Incase you change the service password here make sure to change in other places of script
			$emailDomain = "corp.ais.com"  
			createServiceUser -ou $services.distinguishedName -userName "SPFarm" -password $dummyPassword -emailDomain $emailDomain
			createServiceUser -ou $services.distinguishedName -userName "SPService" -password $dummyPassword -emailDomain $emailDomain
			createServiceUser -ou $services.distinguishedName -userName "SPContent" -password $dummyPassword -emailDomain $emailDomain
			createServiceUser -ou $services.distinguishedName -userName "SPSearch" -password $dummyPassword -emailDomain $emailDomain 
			createServiceUser -ou $services.distinguishedName -userName "SPUPS" -password $dummyPassword -emailDomain $emailDomain 
			createServiceUser -ou $services.distinguishedName -userName "SQLService" -password $dummyPassword -emailDomain $emailDomain
			createServiceUser -ou $services.distinguishedName -userName "SQLAgent" -password $dummyPassword -emailDomain $emailDomain
			createServiceUser -ou $services.distinguishedName -userName "SQLReporting" -password $dummyPassword -emailDomain $emailDomain  
			$c = 1   
			#Adds dummy users with ID Fn1.ln1 to fn99.ln99 with fakepassword as password
			do 
			{    
				$firstName = "fn1" + $c  
				$lastName = "ln" + $c   
				createUser -ou $employees.distinguishedName -firstName $firstName -lastName $lastName -password $dummyPassword -emailDomain $emailDomain  
				$c++
			} while ($c -le 101)

		}  -PSConnectionUri $connectionUri -PSCredential $cred 
    }
    catch [System.Exception]
    {
		"Adding active directory users failed $connectionUri"
    }
    "Adding active directory users complete $connectionUri"
    #endregion add AD service accounts and users 
}

####################################################################
# Updates the SQL Server by opening firewall port
# Change the service account to run using farm service accounts
# Changes max degree of parallelism to 1
#####################################################################
workflow UpdateSQLServer($connectionUri, $sqlcred,$ip)
{
	WaitFor-SysRestart -connectionUri $connectionUri -cred $sqlcred
        
    "Making SQL server service changes"
    #region change sql server service accounts and add the SPFarm as admin
    inlineScript
    {	
		#Generate a schedule task to set the DNS, so that it will work on export on import.
	    Set-Content  "c:\SetDNS.ps1" " `$nics =Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName 'localhost' -ErrorAction Inquire | Where{`$_.IPEnabled -eq 'TRUE'}
                    `$newDNS = $ip
                     foreach(`$nic in `$nics)
                     {
                     `$nic.SetDNSServerSearchOrder(`$newDNS)
                     }"
        $TaskRun = "powershell.exe -f c:\SetDNS.ps1"
        schtasks /create /sc ONSTART /tn "SETDNS" /tr $TaskRun /ru System
	  
	  	#Add access to SQL port in firewall
	 	CMD /C "netsh advfirewall firewall add rule name=""Port 1433"" dir=in action=allow protocol=TCP localport=1433"
  
        # configure SQL Server 2012 services (engine, agent, reporting) in order to use these domain accounts
        $account1="corpAIS\SQLService"
        $password1="Passw0rd"
        $service1="name='MSSQLSERVER'"		
        $svc1=gwmi win32_service -filter $service1
        $svc1.StopService()
        $svc1.change($null,$null,$null,$null,$null,$null,$account1,$password1,$null,$null,$null)
        $svc1.StartService()

        $account2="corpAIS\SQLAgent"
        $password2="Passw0rd"
        $service2="name='SQLSERVERAGENT'"

        $svc2=gwmi win32_service -filter $service2
        $svc2.StopService()
        $svc2.change($null,$null,$null,$null,$null,$null,$account2,$password2,$null,$null,$null)
        $svc2.StartService()
    
        $serviceBrowser="name='SQLBrowser'"
        $svcBrowser=gwmi win32_service -filter $serviceBrowser
        $svcBrowser.ChangeStartMode("Automatic") 
        $svcBrowser.StartService()

        $account3="corpAIS\SQLReporting"
        $password3="Passw0rd"
        $service3="name='ReportServer'"

        $svc3=gwmi win32_service -filter $service3
        $svc3.StopService()
        $svc3.change($null,$null,$null,$null,$null,$null,$account3,$password3,$null,$null,$null)
        $svc3.StartService()

        Start-Sleep -seconds 60

        #enable named pipes for the server to execute script
        # Load the assemblies
        [reflection.assembly]::LoadWithPartialName("Microsoft.SqlServer.Smo")
        [reflection.assembly]::LoadWithPartialName("Microsoft.SqlServer.SqlWmiManagement")

        $smo = 'Microsoft.SqlServer.Management.Smo.'
        $wmi = new-object ($smo + 'Wmi.ManagedComputer').
        # Enable the named pipes protocol for the default instance.
        $uri = "ManagedComputer[@Name='" + (get-item env:\computername).Value + "']/ ServerInstance[@Name='MSSQLSERVER']/ServerProtocol[@Name='Np']"
        $Np = $wmi.GetSmoObject($uri)
        $Np.IsEnabled = $true
        $Np.Alter()
        $Np

        # Get a reference to the default instance of the Database Engine.
        $DfltInstance = $Wmi.Services['MSSQLSERVER']
        # Display the state of the service.
        $DfltInstance
        # Stop the service.
        $DfltInstance.Stop();
        # Wait until the service has time to stop.
        # Refresh the cache.
        $DfltInstance.Refresh(); 
        # Display the state of the service.
        $DfltInstance
        # Start the service again.
        $DfltInstance.Start();
        # Wait until the service has time to start.
        # Refresh the cache and display the state of the service.
        $DfltInstance.Refresh(); 
        $DfltInstance
    } -PSConnectionUri $connectionUri -PSCredential $sqlcred 
   
   "Making SQL server service changes complete"
    Start-Sleep -Seconds 15
    Restart-VM -connectionUri $connectionUri -cred $sqlcred
    Start-Sleep -Seconds 15
    WaitFor-SysRestart -connectionUri $connectionUri -cred $sqlcred 
    Start-Sleep -Seconds 30
    
    "Running SQL server scripts"
    inlineScript
    {
		cd "C:\Program Files (x86)\Microsoft SQL Server\110\Tools\PowerShell\Modules\SQLPS"
		$framework=$([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())
		Set-Alias installutil "$($framework)installutil.exe"
		installutil Microsoft.SqlServer.Management.PSSnapins.dll
		installutil Microsoft.SqlServer.Management.PSProvider.dll
		Add-PSSnapin SqlServerCmdletSnapin110
		Add-PSSnapin SqlServerProviderSnapin110
     
        # configure the SPFarm account in roles securityadmin and dbcreator onto the SQL Server engine
		#set max degree of parallelism to 1
        Invoke-Sqlcmd -ServerInstance . -Database master –Query `
        "USE [master] 
        GO 
        CREATE LOGIN [corpAIS\SPFarm] FROM WINDOWS WITH DEFAULT_DATABASE=[master] 
        GO 
        ALTER SERVER ROLE [dbcreator] ADD MEMBER [corpAIS\SPFarm] 
        GO 
        ALTER SERVER ROLE [securityadmin] ADD MEMBER [corpAIS\SPFarm] 
        GO
        ALTER SERVER ROLE [serveradmin] ADD MEMBER [corpAIS\SPFarm] 
        GO
        
        sp_configure 'show advanced options', 1;
        GO
        RECONFIGURE WITH OVERRIDE;
        GO
        sp_configure 'max degree of parallelism', 1;
        GO
        RECONFIGURE WITH OVERRIDE;
        GO"

		#Add SPFarm service as Admin
        $group = [ADSI]("WinNT://"+$env:COMPUTERNAME+"/administrators,group")
        $group.add("WinNT://CORPAIS/SPFARM")

    } -PSConnectionUri $connectionUri  -PSCredential $sqlcred 
    #endregion change sql server service accounts and add the SPFarm as admin
   
   	"Running SQL server scripts complete"
}

####################################################################
# Creates a Farm from SVR Machine 1
# creates central Admin on port 2222
#####################################################################
workflow CreateServerFarm($connectionUri, $cred,$clsName,$port,$ip)
{
    "Adding farm as admin $connectionUri"
    inlineScript
    {	
		Enable-WSManCredSSP –Role Server -Force
		$group = [ADSI]("WinNT://"+$env:COMPUTERNAME+"/administrators,group")
        $group.add("WinNT://CORPAIS/SPFARM")
		
		Set-Content  "c:\SetDNS.ps1" "`$card=  Get-NetIPInterface -ConnectionState Connected -AddressFamily IPv4 -Dhcp Enabled
        Set-DnsClientServerAddress -InterfaceAlias `$card.InterfaceAlias -ServerAddresses  '$USING:ip'"
        $TaskRun = "powershell.exe -f c:\SetDNS.ps1"
        schtasks /create /sc ONSTART /tn "SETDNS" /tr $TaskRun /ru System
    
    } -PSConnectionUri $connectionUri   -PSCredential $cred 
  
    "Adding farm as admin complete $clsName"
    #run below script as farm 
    $Password = "Passw0rd"
    $credPass = convertto-securestring -AsPlainText -Force -String $Password
	$framcred = new-object -typename System.Management.Automation.PSCredential -argumentlist "CORPAIS\SPFarm",$credPass

    "Creating  farm  $clsName : $port"
    inlineScript
    {           
        ############################################################
        # Configures a SharePoint 2013 farm with custom: 
        # Configuration Database 
        # Central Administation Database
        # Central Administation web application and site 
        ############################################################  

        Add-PSSnapin Microsoft.SharePoint.PowerShell -erroraction SilentlyContinue   

        ## Settings ## 
        $sqlVMName ="SP2013SQL1"
        $configDatabaseName = "SP2013_Farm_SharePoint_Config"
        $sqlServer = $sqlVMName
        $sqlServerAlias = "SP2013SQL" 
        $caDatabaseName = "SP2013_Farm_Admin_Content"
        $caPort = 2222 
        $caAuthN = "NTLM" 
        $passphrase = "pass@word1" 
        $sPassphrase = (ConvertTo-SecureString -String $passphrase -AsPlainText -force)  

        ######################################## 
        # Create the SQL Alias 
        ########################################  

        $x86 = "HKLM:\Software\Microsoft\MSSQLServer\Client\ConnectTo"  
        $x64 = "HKLM:\Software\Wow6432Node\Microsoft\MSSQLServer\Client\ConnectTo"     
        if ((test-path -path $x86) -ne $True)   
        {  
            "$x86 doesn't exist"       
            New-Item $x86 
        }   
        if ((test-path -path $x64) -ne $True)  
        {     
            "$x64 doesn't exist"  
            New-Item $x64 
        }    

        $TCPAlias = "DBMSSOCN," + $SQLServer  

        New-ItemProperty -Path $x86 -Name $sqlServerAlias -PropertyType String -Value $TCPAlias  
        New-ItemProperty -Path $x64 -Name $sqlServerAlias -PropertyType String -Value $TCPAlias   
 
        ######################################## 
        # Create the farm 
        ######################################## 
        $domain = "CorpAIS" #"corp.ais.com"
        $password = "Passw0rd" | ConvertTo-SecureString -asPlainText -Force
        $username = "$domain\SPFarm" 
        $credential = New-Object System.Management.Automation.PSCredential($username,$password)

            "Creating the configuration database $configDatabaseName"  
        New-SPConfigurationDatabase –DatabaseName $configDatabaseName –DatabaseServer $sqlServerAlias –AdministrationContentDatabaseName $caDatabaseName –Passphrase $sPassphrase –FarmCredentials $credential  
        $farm = Get-SPFarm 

        if (!$farm -or $farm.Status -ne "Online") 
        { 
            "Farm was not created or is not running";
            exit;
        }  

        # Perform the config wizard tasks

        "Initialize security"
        Initialize-SPResourceSecurity  

        "Install services"
        Install-SPService  

        "Register features"
        Install-SPFeature -AllExistingFeatures  

        "Create the Central Administration site on port $caPort" 
        New-SPCentralAdministration -Port $caPort -WindowsAuthProvider $caAuthN  

        "Install Help Collections"
        Install-SPHelpCollection -All  

        "Install Application Content" 
        Install-SPApplicationContent  

        New-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name "DisableLoopbackCheck" -value "1" -PropertyType dword  

        # $ServiceConnectionPoint = get-SPTopologyServiceApplication | select URI
        # Set-SPFarmConfig -ServiceConnectionPointBindingInformation $ServiceConnectionPoint -Confirm:$False

    } -PSComputerName $clsName -PSSessionOption (New-PSSessionOPtion -SkipCACheck -SkipCNCheck) -PSPort  $port -PSUseSsl $true -PSCredential $framcred -PSAuthentication CredSSP   
    "Creating  farm  complete $cloudSvcName"       
    
	Start-Sleep -Seconds 60;
}

####################################################################
# Join SVR2 to farm created by SVR1 Machine 1
#####################################################################
workflow JoinSharePointFarm( $connectionUri,$cred ,$clsName,$port,$ip)
{
    "Adding farm as admin  $connectionUri"
    inlineScript
    {
	 	$group = [ADSI]("WinNT://"+$env:COMPUTERNAME+"/administrators,group")
     	$group.add("WinNT://CORPAIS/SPFARM")
		Enable-WSManCredSSP –Role Server -Force
       
        Set-Content  "c:\SetDNS.ps1" "`$card=  Get-NetIPInterface -ConnectionState Connected -AddressFamily IPv4 -Dhcp Enabled
        Set-DnsClientServerAddress -InterfaceAlias `$card.InterfaceAlias -ServerAddresses  '$USING:ip'"
        $TaskRun = "powershell.exe -f c:\SetDNS.ps1"
        schtasks /create /sc ONSTART /tn "SETDNS" /tr $TaskRun /ru System
 
    } -PSConnectionUri $connectionUri  -PSCredential $cred
  
    "Adding farm as admin complete $connectionUri"
    #run below script as farm 
    $Password = "Passw0rd"
    $credPass = convertto-securestring -AsPlainText -Force -String $Password
	$framcred = new-object -typename System.Management.Automation.PSCredential -argumentlist "CORPAIS\SPFarm",$credPass

    "Joining farm $clsName"
    # Join SharePoint Server SP2013SRV2 to Farm. 
    inlineScript
    {     
        Add-PSSnapin Microsoft.SharePoint.PowerShell -erroraction SilentlyContinue   

        ## Settings ## 

        $sqlVMName ="SP2013SQL1"
        $configDatabaseName = "SP2013_Farm_SharePoint_Config" 
        $sqlServer = $sqlVMName 
        $sqlServerAlias = "SP2013SQL"  
        $passphrase = "pass@word1" 
        $sPassphrase = (ConvertTo-SecureString -String $passphrase -AsPlainText -force)  
      
        # Create the SQL Alias       
        $x86 = "HKLM:\Software\Microsoft\MSSQLServer\Client\ConnectTo"
        $x64 = "HKLM:\Software\Wow6432Node\Microsoft\MSSQLServer\Client\ConnectTo"
                
        if ((test-path -path $x86) -ne $True)   
        {       
            "$x86 doesn't exist"
            New-Item $x86   
        }
        
        if ((test-path -path $x64) -ne $True)   
        {      
            "$x64 doesn't exist"          
            New-Item $x64   
        }
        
        $TCPAlias = "DBMSSOCN," + $SQLServer    
        
        New-ItemProperty -Path $x86 -Name $sqlServerAlias -PropertyType String -Value $TCPAlias   
        
        New-ItemProperty -Path $x64 -Name $sqlServerAlias -PropertyType String -Value $TCPAlias   

        ######################################## 
        # Connect to the farm 
        ######################################## 
        
        "Connecting to the configuration database $configDatabaseName"  
        
        # psconfig -cmd upgrade -inplace b2b -wait -force 
        
        Connect-SPConfigurationDatabase -DatabaseServer $sqlServerAlias -DatabaseName $configDatabaseName -Passphrase $sPassphrase  
        $farm = Get-SPFarm 
        if (!$farm -or $farm.Status -ne "Online") 
        {  
            "Farm was not connected or is not running"  
            exit
        }  
        
        # Perform the config wizard tasks Write-Output "Initialize security" Initialize-SPResourceSecurity  
    
        "Install services" 
        Install-SPService  
        "Register features" 
        Install-SPFeature -AllExistingFeatures  
        New-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name "DisableLoopbackCheck" -value "1" -PropertyType dword 

    }  -PSComputerName $clsName -PSSessionOption (New-PSSessionOPtion -SkipCACheck -SkipCNCheck) -PSPort  $port -PSUseSsl $true -PSCredential $framcred -PSAuthentication CredSSP   

    "Joining farm complete $clsName"

}

####################################################################
# Deploys various Sharepoint Services on Server 1
#####################################################################
workflow ConfigureServicesAndDeploySite( $clsName,$port )
{
 	#run below script as farm 
    $Password = "Passw0rd"
    $credPass = convertto-securestring -AsPlainText -Force -String $Password
	$framcred = new-object -typename System.Management.Automation.PSCredential -argumentlist "CORPAIS\SPFarm",$credPass

    "Configuring Services started"
    inlineScript
    {
        ## Farm Initial Configuration ##  
        
        Add-PSSnapin Microsoft.SharePoint.PowerShell -erroraction SilentlyContinue   
        
        ## Settings ## 
        $databaseServerName = "SP2013SQL1"  
        $saAppPoolName = "SharePoint Web Services" 
        $appPoolUserName = "corpAIS\SPService"  
        
        # Retrieve or create the services application pool and managed account 
        $saAppPool = Get-SPServiceApplicationPool -Identity $saAppPoolName -EA 0
          
        if($saAppPool -eq $null)  
        {
            "Creating Service Application Pool..."      
            $appPoolAccount = Get-SPManagedAccount -Identity $appPoolUserName -EA 0    
            
            if($appPoolAccount -eq $null)    
            {        
                $password = "Passw0rd" | ConvertTo-SecureString -asPlainText -Force
                $username = $appPoolUserName
                $appPoolCred = New-Object System.Management.Automation.PSCredential($username,$password)
                $appPoolAccount = New-SPManagedAccount -Credential $appPoolCred -EA 0    
            }       
            
            $appPoolAccount = Get-SPManagedAccount -Identity $appPoolUserName -EA 0       
            
            if($appPoolAccount -eq $null)    
            {      
                "Cannot create or find the managed account $appPoolUserName, please ensure the account exists."    
                Exit -1    
            }    
            
           New-SPServiceApplicationPool -Name $saAppPoolName -Account $appPoolAccount -EA 0 > $null  
        } 
           
        # provision the Web Analytics and Health Data Collection service, together with the Usage service, and the State service.  
        $usageSAName = "Usage and Health Data Collection Service" 
        $stateSAName = "State Service" 
        $stateServiceDatabaseName = "SP2013_Farm_StateDB"  

        # Configure the web analytics and health data collection service before creating the service  
        Set-SPUsageService -LoggingEnabled 1 -UsageLogLocation "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\15\LOGS\" -UsageLogMaxSpaceGB 2  
           
        # Usage Service Write-Host "Creating Usage Service and Proxy..." 
        $serviceInstance = Get-SPUsageService
         New-SPUsageApplication -Name $usageSAName -DatabaseServer $databaseServerName -DatabaseName "SP2013_Farm_UsageDB" -UsageService $serviceInstance > $null  
           
        # State Service 
        $stateServiceDatabase = New-SPStateServiceDatabase -Name $stateServiceDatabaseName 

        $stateSA = New-SPStateServiceApplication -Name $stateSAName -Database $stateServiceDatabase
        New-SPStateServiceApplicationProxy -ServiceApplication $stateSA -Name "$stateSAName Proxy" -DefaultProxyGroup 

        # provision the Managed Metadata service application. 
        $metadataSAName = "Managed Metadata Service"  
           
        # Managed Metadata Service 
        "Creating Metadata Service and Proxy..." 
        $mmsApp = New-SPMetadataServiceApplication -Name $metadataSAName -ApplicationPool $saAppPoolName -DatabaseServer $databaseServerName -DatabaseName "SP2013_Farm_MetadataDB" > $null 
        New-SPMetadataServiceApplicationProxy -Name "$metadataSAName Proxy" -DefaultProxyGroup -ServiceApplication $metadataSAName > $null 
        Get-SPServiceInstance | where-object {$_.TypeName -eq "Managed Metadata Web Service"} | Start-SPServiceInstance > $null 

        # Search Service - START # 
        $sp1VMName="SP2013SRV1"
           
        $searchMachines = @($sp1VMName)
        $searchQueryMachines = @($sp1VMName)
        $searchCrawlerMachines = @($sp1VMName)
        $searchAdminComponentMachine = $sp1VMName
        $searchSAName = "Search Service"
        $saAppPoolName = "SharePoint Web Services" 
        $databaseServerName = "SP2013SQL1" 
        $searchDatabaseName = "SP2013_Farm_Search" 
        $indexLocation = "C:\SearchIndex"  

        cmd /c "mkdir $indexLocation"

        "Creating Search Service and Proxy..." 
        "  Starting Services..."  

        foreach ($machine in $searchMachines) 
        {    
            "    Starting Search Services on $machine"    
            Start-SPEnterpriseSearchQueryAndSiteSettingsServiceInstance $machine -ErrorAction SilentlyContinue     
            Start-SPEnterpriseSearchServiceInstance $machine -ErrorAction SilentlyContinue 
        } 

        "  Creating Search Application..." 
        $searchApp = Get-SPEnterpriseSearchServiceApplication -Identity $searchSAName -ErrorAction SilentlyContinue

        if (!$searchApp) 
        {  
            $searchApp = New-SPEnterpriseSearchServiceApplication -Name $SearchSAName -ApplicationPool $saAppPoolName -DatabaseServer $databaseServerName -DatabaseName $searchDatabaseName 
        } 

        $searchInstance = Get-SPEnterpriseSearchServiceInstance -Local  

        # Define the search topology 

        "  Defining the Search Topology..."
        $initialSearchTopology = $searchApp | Get-SPEnterpriseSearchTopology -Active
        $newSearchTopology = $searchApp | New-SPEnterpriseSearchTopology   

        # Create search components 

        "  Creating Admin Component..." 
        New-SPEnterpriseSearchAdminComponent -SearchTopology $newSearchTopology -SearchServiceInstance $searchInstance  

        "  Creating Analytics Component..." 
        New-SPEnterpriseSearchAnalyticsProcessingComponent -SearchTopology $newSearchTopology -SearchServiceInstance $searchInstance  

        "  Creating Content Processing Component..." 
        New-SPEnterpriseSearchContentProcessingComponent -SearchTopology $newSearchTopology -SearchServiceInstance $searchInstance  

        "  Creating Query Processing Component..." 
        New-SPEnterpriseSearchQueryProcessingComponent -SearchTopology $newSearchTopology -SearchServiceInstance $searchInstance  

        "  Creating Crawl Component..." 
        New-SPEnterpriseSearchCrawlComponent -SearchTopology $newSearchTopology -SearchServiceInstance $searchInstance   

        "  Creating Index Component..." 
        New-SPEnterpriseSearchIndexComponent -SearchTopology $newSearchTopology -SearchServiceInstance $searchInstance -RootDirectory $indexLocation   

        "  Activating the new topology..."
        $newSearchTopology.Activate()  

        "  Creating Search Application Proxy..." 

        $searchProxy = Get-SPEnterpriseSearchServiceApplicationProxy -Identity "$searchSAName Proxy" -ErrorAction SilentlyContinue 

        if (!$searchProxy) 
        {    
            New-SPEnterpriseSearchServiceApplicationProxy -Name "$searchSAName Proxy" -SearchApplication $searchSAName 
        } 

        # Search Service - END # 

        # User Profile Service #

        "Creating User Profile Service and Proxy acting as Farm account..."
        $sb =  {  
                       Add-PSSnapin Microsoft.SharePoint.PowerShell -erroraction SilentlyContinue   
                       "Creating User Profile Service and Proxy acting as Farm account..."  
                       $saAppPoolNameForUPS = "SharePoint Web Services"  
                       $saAppPoolForUPS = Get-SPServiceApplicationPool -Identity $saAppPoolNameForUPS -EA 0   
                       $userUPSName = "User Profile Service"   
                       $databaseServerNameForUPS = "SP2013SQL1"  
                       $userProfileService = New-SPProfileServiceApplication -Name $userUPSName -ApplicationPool $saAppPoolNameForUPS -ProfileDBServer $databaseServerNameForUPS -ProfileDBName "SP2013_Farm_ProfileDB" -SocialDBServer $databaseServerNameForUPS -SocialDBName "SP2013_Farm_SocialDB" -ProfileSyncDBServer $databaseServerNameForUPS -ProfileSyncDBName "SP2013_Farm_SyncDB" 
                       New-SPProfileServiceApplicationProxy -Name "$userUPSName Proxy" -ServiceApplication $userProfileService -DefaultProxyGroup > $null 
                  } 

        $farmAccount = (Get-SPFarm).DefaultServiceAccount 
       
        $password = "Passw0rd" | ConvertTo-SecureString -asPlainText -Force
        $username = $farmAccount 
        $farmCredential = New-Object System.Management.Automation.PSCredential($username,$password)
       
        $job = Start-Job -Credential $farmCredential -ScriptBlock $sb | Wait-Job  

        Get-SPServiceInstance | where-object {$_.TypeName -eq "User Profile Service"} | Start-SPServiceInstance > $null

        $subSettingstName = "Subscription Settings Service1" 
        $subSettingstDatabaseName = "SP2013_Farm_SubSettingsDB1" 
        $appManagementName = "App Management Service1" 
        $appManagementDatabaseName = "SP2013_Farm_AppManagementDB1"  

        "Creating Subscription Settings Service and Proxy..." 
        $subSvc = New-SPSubscriptionSettingsServiceApplication –ApplicationPool $saAppPoolName –Name $subSettingstName –DatabaseName $subSettingstDatabaseName 
        $subSvcProxy = New-SPSubscriptionSettingsServiceApplicationProxy –ServiceApplication $subSvc 
        Get-SPServiceInstance | where-object {$_.TypeName -eq $subSettingstName} | Start-SPServiceInstance > $null  
                   

    }-PSComputerName $clsName -PSSessionOption (New-PSSessionOPtion -SkipCACheck -SkipCNCheck) -PSPort  $port -PSUseSsl $true -PSCredential $framcred -PSAuthentication CredSSP   
    "Configuring Services Complete"
}

#helper function from http://michaelwasham.com/2013/04/16/windows-azure-powershell-updates-for-iaas-ga/
#installs the VM certificate on local machine as trusted
function InstallWinRMCert($serviceName, $vmname)
{
    $winRMCert = (Get-AzureVM -ServiceName $serviceName -Name $vmname | select -ExpandProperty vm).DefaultWinRMCertificateThumbprint
    $AzureX509cert = Get-AzureCertificate -ServiceName $serviceName -Thumbprint $winRMCert -ThumbprintAlgorithm sha1

    $certTempFile = [IO.Path]::GetTempFileName()
    $certTempFile
    $AzureX509cert.Data | Out-File $certTempFile

    # Target The Cert That Needs To Be Imported
    $CertToImport = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $certTempFile
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store "Root", "LocalMachine"
    $store.Certificates.Count
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $store.Add($CertToImport)
    $store.Close()

    Remove-Item $certTempFile
}

#Main script to deply the farm
workflow Main($StorageAccountName,$SubnetName,$AFGName,$VnetName)
{
	#Generate a random string so that clous service name will not conflict with other deployments
 	$RandStr = InlineScript
    {
        $rand = New-Object -TypeName System.Random
        $RandStr =""
        1..5 | ForEach { $RandStr = $RandStr + [char]$rand.next( 97,122) }
        $RandStr
    }	

	"Random String $RandStr"
	
    $DCServiceName = "SP2013-AIS-"+$RandStr+"-DC"
    $SQLServiceName = "SP2013-AIS-"+$RandStr+"-SQL"
    $SPSVR1ServiceName = "SP2013-AIS-"+$RandStr+"-SVR1"
    $SPSVR2ServiceName = "SP2013-AIS-"+$RandStr+"-SVR2"
		
	#region variables
    $WindowsServer2012Image ="a699494373c04fc0bc8f2bb1389d6106__Windows-Server-2012-Datacenter-201302.01-en.us-30GB.vhd"
    $SQLServerImage="fb83b3509582419d99629ce476bcb5c8__Microsoft-SQL-Server-2012SP1-Enterprise-CY13SU04-SQL11-SP1-CU3-11.0.3350.0-B"
	$SharePointImage="c6e0f177abd8496e934234bd27f46c5d__SharePoint-2013-Trial-4-13-2013"
	$AdminUserName="SPUser"		 #Login userName for all the VMs created...
	$Password = "SharePoint@123" #Login password for all the VMs created...
  	$DCVmName ="SP2013DC1"       #AD VM name
	$SQLVMName ="SP2013SQL1"	 #SQL Server VM name
	$SP1SVRVMName="SP2013SRV1"	 #SP Farm server 1
	$SP2SVRVMName="sp2013srv2"   #SP Farm server 2
	$AvailabilitySetName="SPAvailabilitySet"
	#endregion variables 
	
	
	#region validate parameters
	$IsAffinityCorrect = Get-AzureAffinityGroup -Name $AFGName
    if($IsAffinityCorrect  -eq $false)
    {
        "Affinity group does not exist"
	    exit
    }
    "Affinity group test passed"	
	$UniqueServiceName = Test-AzureName -Service $DCServiceName
    if($UniqueServiceName  -ne $false)
    {
        "DC Cloud Service name $DCServiceName already taken"
	    exit
    }
	$UniqueServiceName = Test-AzureName -Service $SQLServiceName
    if($UniqueServiceName  -ne $false)
    {
        "SQL Cloud Service name $SQLServiceName already taken"
	    exit
    }
	$UniqueServiceName = Test-AzureName -Service $SPSVR1ServiceName
    if($UniqueServiceName  -ne $false)
    {
        "SP Server 1 Cloud Service name $SPSVR1ServiceName already taken"
	    exit
    }
	$UniqueServiceName = Test-AzureName -Service $SPSVR2ServiceName
    if($UniqueServiceName  -ne $false)
    {
        "SP Server 2 Cloud Service name $SPSVR2ServiceName already taken"
	    exit
    }
   	"Cloud Services names are Unique"
   
   	try
	{
	  Get-AzureStorageAccount -StorageAccountName $StorageAccountName
	}
	catch [System.Exception]
	{
	  "Invalid Storage Account $StorageAccountName"
	}
	
	"Storage accout name valid"
	#endregion validate parameters
	
	$myDNS = New-AzureDNS -Name 'myDNS' -IPAddress '127.0.0.1'
	
	"Creating Active Directory VM"
	#Create Active Directory VM
	InlineScript
	{
		$MyDC = New-AzureVMConfig -name $USING:DCVmName -InstanceSize 'Small' -ImageName $USING:WindowsServer2012Image |
	    Add-AzureProvisioningConfig -Windows -AdminUsername $USING:AdminUserName -Password $USING:Password |
		Add-AzureEndpoint -Name 'WinRemote' -LocalPort 5985 -Protocol tcp -PublicPort 5985 |
		Add-AzureEndpoint -Name "http" -Protocol tcp -LocalPort 80 -PublicPort 80 |
	    Set-AzureSubnet -SubnetNames $USING:SubnetName			
		New-AzureVM -ServiceName $USING:DCServiceName -AffinityGroup $USING:AFGName -VMs $MyDC -DnsSettings $USING:myDNS  -VNetName $USING:VnetName -WaitForBoot
	} 
	"Creating Active Directory VM Created"
	#Get the WinRm Url and install the AD machine certificate for remote commands
	$DCConnectionUri = Get-AzureWinRMUri -ServiceName $DCServiceName -Name $DCVmName 
	"DCConnectionUri :$DCConnectionUri"
	InstallWinRMCert -serviceName  $DCServiceName  -vmname $DCVmName 
	
	#Get the cedentials
	$credPass = convertto-securestring -AsPlainText -Force -String $Password
	$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $AdminUserName,$credPass  	
		
	Checkpoint-Workflow
	InstallAD  -connectionUri $DCConnectionUri.ToString() -cred $cred 
	Checkpoint-Workflow
	
	#Get the IP address of the domain machine so that it can be passed as DNS IP address to other machines
	$ADIPAddress=InlineScript
	{
		Get-NetAdapter | ? status -eq 'up' | Get-NetIPAddress -ea 0|where addressfamily -eq 'IPv4' 
	} -PSConnectionUri $DCConnectionUri.ToString()  -PSCredential $cred
    $DomainServerIP = $ADIPAddress.ipaddress

	$myDNS = New-AzureDNS -Name 'DCDNS' -IPAddress $DomainServerIP		
	
	"Deploying SQL and front end server deployment"
    
	InlineScript
    {
	    # SQL Servers Service 
	    $StorageUriBase = "https://" + $USING:StorageAccountName + ".blob.core.windows.net/vhds/"
	    $SQLServersName = "SP2013-AIS-SQL" 
	    $SQLServersLabel = "SP2013-AIS-SQL" 
	    $SQLServersDescription = "SP2013 SQL Servers" 
	    $SQLServers = @() 
	    $SQLDiskSize = 100 
	    $SQLDataDiskLabel = "DataDisk" 
	    $SQLDataDiskName = "Data Disk" 
	    $SQLLogDiskLabel = "LogDisk"
	    $SQLLogDiskName = "Log Disk"
	    $SQLTempDbDiskLabel = "TempDbDisk" 
	    $SQLTempDbDiskName = "TempDb Disk" 
      	$SQLnDataDiskMediaLocation = $StorageUriBase + $USING:SQLServiceName + $SQLServer + "datadisk01.vhd"
	    $SQLnLogDiskMediaLocation = $StorageUriBase + $USING:SQLServiceName + $SQLServer + "logdisk01.vhd" 
	    $SQLnTempDbDiskMediaLocation = $StorageUriBase + $USING:SQLServiceName + $SQLServer + "tempdbdisk01.vhd"
	    $SQLnName = $USING:SQLVMName 
	    $SQLnLabel = $USING:SQLVMName
	    $SQLnSize = "Large" 
	    $SQLnSysDiskMediaLocation = "https://" + $USING:StorageAccountName + ".blob.core.windows.net/vhds/sp2013sql" + $SQLServer + "systemdisk01.vhd"
	    $SQLnDataDiskLabel = $SQLnLabel + $SQLDataDiskLabel
	    $SQLnLogDiskLabel = $SQLnLabel + $SQLLogDiskLabel
	    $SQLnTempDbDiskLabel = $SQLnLabel + $SQLTempDbDiskLabel 
	    $SQLn = New-AzureVMConfig -Name $SQLnName -ImageName $USING:SQLServerImage -InstanceSize $SQLnSize -Label $SQLnLabel -MediaLocation $SQLnSysDiskMediaLocation | 
	    Add-AzureProvisioningConfig -WindowsDomain -AdminUsername $USING:AdminUserName -Password $USING:Password -Domain 'CORPAIS' -DomainPassword $USING:Password -DomainUserName 'SPUser' -JoinDomain 'corp.ais.com'|
        Add-AzureDataDisk -CreateNew -DiskSizeInGB $SQLDiskSize -DiskLabel $SQLnDataDiskLabel -LUN 0 -MediaLocation $SQLnDataDiskMediaLocation | 
	    Add-AzureDataDisk -CreateNew -DiskSizeInGB $SQLDiskSize -DiskLabel $SQLnLogDiskLabel -LUN 1 -MediaLocation $SQLnLogDiskMediaLocation |
	    Add-AzureDataDisk -CreateNew -DiskSizeInGB $SQLDiskSize -DiskLabel $SQLnTempDbDiskLabel -LUN 2 -MediaLocation $SQLnTempDbDiskMediaLocation |
	    Set-AzureSubnet $USING:SubnetName 
	    $SQLServers += $SQLn 	    
		New-AzureVM -ServiceName $USING:SQLServiceName -VNetName $USING:VnetName -AffinityGroup $USING:AFGName -VMs $SQLServers -DnsSettings $USING:myDNS 
	}
	
	$StorageUriBase = "https://" + $StorageAccountName + ".blob.core.windows.net/vhds/"
    InlineScript
    {   $Count =1
        $SPServersLabel = "SP2013-AIS-SP"
        $SPServersDescription = "SP2013 SharePoint Servers"
        $SPServers = @()   
        $pp = $USING:ports
        $SPAPPnName = $USING:SPSVR1ServiceName + $count
        $SPAPPnLabel = $USING:SPSVR1ServiceName + $count
        $SPAPPnSize = "Medium"
        $SPAPPnSysDiskMediaLocation = $USING:StorageUriBase + $SPAPPnName+ "systemdisk01.vhd" 
        $SPAPPn = New-AzureVMConfig -Name $USING:SP1SVRVMName -AvailabilitySetName  $USING:AvailabilitySetName -ImageName $USING:SharePointImage -InstanceSize $SPAPPnSize -Label $SPAPPnLabel -MediaLocation $SPAPPnSysDiskMediaLocation | 
        Add-AzureEndpoint -Name "httpS1" -Protocol tcp -LocalPort 80 -PublicPort 80 |
        Add-AzureProvisioningConfig -WindowsDomain -AdminUsername $USING:AdminUserName -Password $USING:Password -Domain 'CORPAIS' -DomainPassword $USING:Password -DomainUserName 'SPUser' -JoinDomain 'corp.ais.com'|
	    Set-AzureSubnet $USING:SubnetName 
        $SPServers += $SPAPPn 
	  	New-AzureVM -ServiceName $USING:SPSVR1ServiceName -VNetName $USING:VnetName -AffinityGroup $USING:AFGName -VMs $SPServers -DnsSettings $USING:myDNS
    }    
	
	InlineScript
    {   
		$Count = 2
        $SPServersLabel = "SP2013-AIS-SP"
        $SPServersDescription = "SP2013 SharePoint Servers"
        $SPServers = @()   
        $pp = $USING:ports
        $SPAPPnName = $USING:SPSVR2ServiceName + $count
        $SPAPPnLabel = $USING:SPSVR2ServiceName + $count 
        $SPAPPnSize = "Medium"
        $SPAPPnSysDiskMediaLocation = $USING:StorageUriBase + $SPAPPnName+ "systemdisk01.vhd" 
        $SPAPPn = New-AzureVMConfig -Name $USING:SP2SVRVMName -AvailabilitySetName $USING:AvailabilitySetName -ImageName $USING:SharePointImage -InstanceSize $SPAPPnSize -Label $SPAPPnLabel -MediaLocation $SPAPPnSysDiskMediaLocation | 
        Add-AzureEndpoint -Name "httpS2" -Protocol tcp -LocalPort 80 -PublicPort 80 |
        Add-AzureProvisioningConfig -WindowsDomain -AdminUsername $USING:AdminUserName -Password $USING:Password -Domain 'CORPAIS' -DomainPassword $USING:Password -DomainUserName 'SPUser' -JoinDomain 'corp.ais.com'|
	    Set-AzureSubnet $USING:SubnetName 
        $SPServers += $SPAPPn 
    	New-AzureVM -ServiceName $USING:SPSVR2ServiceName -VNetName $USING:VnetName -AffinityGroup $USING:AFGName -VMs $SPServers -DnsSettings $USING:myDNS 
    }     
		
	#wait untill all the machine are in Ready role to execute scripts
	do
	{
		"Waiting for servers to boot..."
		$SQL= Get-AzureVM  -ServiceName $SQLServiceName -Name $SQLVMName 		
		$SP1= Get-AzureVM  -ServiceName $SPSVR1ServiceName -Name $SP1SVRVMName 	
		$SP2= Get-AzureVM  -ServiceName $SPSVR2ServiceName -Name $SP2SVRVMName 			
		Start-Sleep -Seconds 15
	}while($SQL.InstanceStatus -ne "ReadyRole" -or $SP1.InstanceStatus -ne "ReadyRole" -or $SP2.InstanceStatus -ne "ReadyRole" )

    Checkpoint-Workflow
   
   	#region install cert from SQL and SP servers to send command using remote powershell
	
	$SQLuri = Get-AzureWinRMUri -ServiceName $SQLServiceName -Name $SQLVMName 
	"SQLURI :$SQLuri"
	InstallWinRMCert -serviceName  $SQLServiceName  -vmname $SQLVMName 
	
	$SPSVR1uri = Get-AzureWinRMUri -ServiceName $SPSVR1ServiceName -Name $SP1SVRVMName 
	"SPSVR1uri :$SPSVR1uri"
	InstallWinRMCert -serviceName  $SPSVR1ServiceName  -vmname $SP1SVRVMName 
	
	$SPSVR2uri = Get-AzureWinRMUri -ServiceName $SPSVR2ServiceName -Name $SP2SVRVMName 
	"SPSVR2uri :$SPSVR2uri"
	InstallWinRMCert -serviceName  $SPSVR2ServiceName  -vmname $SP2SVRVMName
	#endregion install cert from servers
	
	Checkpoint-Workflow
	UpdateSQLServer -connectionUri  $SQLuri -sqlcred $cred -ip $DomainServerIP
	
	#region install SharePoint
	#get port for cred SSP and create initial farm on server 1
	$SPSVR1CloudServiceName= $SPSVR1ServiceName+".cloudapp.net"
	$remsvr1Port=InlineScript
	{
		$ep= Get-AzureVM -ServiceName $USING:SPSVR1ServiceName  -Name $USING:SP1SVRVMName | Get-AzureEndpoint -Name "WinRmHTTPs"
		$ep.Port
	}
	CreateServerFarm -connectionUri $SPSVR1uri -cred $cred -clsName $SPSVR1CloudServiceName -port $remsvr1Port -ip $DomainServerIP
	
	#get port for cred SSP and Join farm on server 2
	$SPSVR2CloudServiceName= $SPSVR2ServiceName+".cloudapp.net"
	$remPort=InlineScript
	{
		$ep= Get-AzureVM -ServiceName $USING:SPSVR2ServiceName  -Name $USING:SP2SVRVMName | Get-AzureEndpoint -Name "WinRmHTTPs"
		$ep.Port
	}
	JoinSharePointFarm -connectionUri $SPSVR2uri -cred $cred -clsName $SPSVR2CloudServiceName -port $remPort -ip $DomainServerIP
	
	#configure services on server 1
	ConfigureServicesAndDeploySite -clsName $SPSVR1CloudServiceName -port $remsvr1Port
	#endregion install SharePoint
	"Farm deployment complete"
}

cls
Get-Date -Format "MMMM dd yyyy HH:mm:ss tt" 
Main -StorageAccountName [yourStorageAccountName] -SubnetName [Subnet] -AFGName [AffinityName] -VnetName [NetworkName]
