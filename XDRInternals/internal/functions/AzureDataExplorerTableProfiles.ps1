function Get-XdrAzureDataExplorerTableProfile {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    @{
        # region Device Timeline Tables (Source = 'DeviceTimeline', RoutingField = 'ActionType')

        XDRDeviceTimelineProcessEvents = @{
            TableName     = 'XDRDeviceTimelineProcessEvents'
            Source        = 'DeviceTimeline'
            RoutingField  = 'ActionType'
            RoutingValues = @(
                'ProcessCreated'
                'CreateRemoteThreadApiCall'
                'OpenProcessApiCall'
                'ProcessCreatedUsingWmiQuery'
                'NtAllocateVirtualMemoryApiCall'
                'NtProtectVirtualMemoryApiCall'
            )
            Columns = @(
                @{ Name = 'ActionTime';                       Type = 'datetime' }
                @{ Name = 'ActionType';                       Type = 'string' }
                @{ Name = 'MachineId';                        Type = 'string' }
                @{ Name = 'MachineName';                      Type = 'string' }
                @{ Name = 'ProcessId';                        Type = 'int' }
                @{ Name = 'ProcessCreationTime';              Type = 'datetime' }
                @{ Name = 'ProcessFileName';                  Type = 'string' }
                @{ Name = 'ProcessFolderPath';                Type = 'string' }
                @{ Name = 'ProcessCommandLine';               Type = 'string' }
                @{ Name = 'ProcessSha1';                      Type = 'string' }
                @{ Name = 'ProcessSha256';                    Type = 'string' }
                @{ Name = 'ProcessAccountName';               Type = 'string' }
                @{ Name = 'ProcessAccountDomain';             Type = 'string' }
                @{ Name = 'ProcessAccountSid';                Type = 'string' }
                @{ Name = 'InitiatingProcessId';              Type = 'int' }
                @{ Name = 'InitiatingProcessCreationTime';    Type = 'datetime' }
                @{ Name = 'InitiatingProcessFileName';        Type = 'string' }
                @{ Name = 'InitiatingProcessFolderPath';      Type = 'string' }
                @{ Name = 'InitiatingProcessCommandLine';     Type = 'string' }
                @{ Name = 'InitiatingProcessSha1';            Type = 'string' }
                @{ Name = 'InitiatingProcessAccountName';     Type = 'string' }
                @{ Name = 'InitiatingProcessAccountDomain';   Type = 'string' }
                @{ Name = 'ReportId';                         Type = 'long' }
                @{ Name = 'SourceProvider';                   Type = 'string' }
                @{ Name = 'Event';                            Type = 'dynamic' }
            )
            ColumnMappings = @(
                @{ Column = 'ActionTime';                     Properties = @{ Path = '$.ActionTime' } }
                @{ Column = 'ActionType';                     Properties = @{ Path = '$.ActionType' } }
                @{ Column = 'MachineId';                      Properties = @{ Path = '$.Machine.MachineId' } }
                @{ Column = 'MachineName';                    Properties = @{ Path = '$.Machine.Name' } }
                @{ Column = 'ProcessId';                      Properties = @{ Path = '$.Process.Id' } }
                @{ Column = 'ProcessCreationTime';            Properties = @{ Path = '$.Process.CreationTime' } }
                @{ Column = 'ProcessFileName';                Properties = @{ Path = '$.Process.ImageFile.FileName' } }
                @{ Column = 'ProcessFolderPath';              Properties = @{ Path = '$.Process.ImageFile.FolderPath' } }
                @{ Column = 'ProcessCommandLine';             Properties = @{ Path = '$.Process.CommandLine' } }
                @{ Column = 'ProcessSha1';                    Properties = @{ Path = '$.Process.ImageFile.Sha1' } }
                @{ Column = 'ProcessSha256';                  Properties = @{ Path = '$.Process.ImageFile.Sha256' } }
                @{ Column = 'ProcessAccountName';             Properties = @{ Path = '$.Process.User.AccountName' } }
                @{ Column = 'ProcessAccountDomain';           Properties = @{ Path = '$.Process.User.AccountDomainName' } }
                @{ Column = 'ProcessAccountSid';              Properties = @{ Path = '$.Process.User.AccountSid' } }
                @{ Column = 'InitiatingProcessId';            Properties = @{ Path = '$.InitiatingProcess.Id' } }
                @{ Column = 'InitiatingProcessCreationTime';  Properties = @{ Path = '$.InitiatingProcess.CreationTime' } }
                @{ Column = 'InitiatingProcessFileName';      Properties = @{ Path = '$.InitiatingProcess.ImageFile.FileName' } }
                @{ Column = 'InitiatingProcessFolderPath';    Properties = @{ Path = '$.InitiatingProcess.ImageFile.FolderPath' } }
                @{ Column = 'InitiatingProcessCommandLine';   Properties = @{ Path = '$.InitiatingProcess.CommandLine' } }
                @{ Column = 'InitiatingProcessSha1';          Properties = @{ Path = '$.InitiatingProcess.ImageFile.Sha1' } }
                @{ Column = 'InitiatingProcessAccountName';   Properties = @{ Path = '$.InitiatingProcess.User.AccountName' } }
                @{ Column = 'InitiatingProcessAccountDomain'; Properties = @{ Path = '$.InitiatingProcess.User.AccountDomainName' } }
                @{ Column = 'ReportId';                       Properties = @{ Path = '$.ReportId' } }
                @{ Column = 'SourceProvider';                 Properties = @{ Path = '$.SourceProvider' } }
                @{ Column = 'Event';                          Properties = @{ Path = '$' } }
            )
        }

        XDRDeviceTimelineFileEvents = @{
            TableName     = 'XDRDeviceTimelineFileEvents'
            Source        = 'DeviceTimeline'
            RoutingField  = 'ActionType'
            RoutingValues = @(
                'FileCreated'
                'FileRenamed'
                'FileDeleted'
                'FileModified'
                'ImageLoaded'
                'ShellLinkCreateFileEvent'
                'ExploitGuardChildProcessAudited'
                'PlistPropertyModified'
            )
            Columns = @(
                @{ Name = 'ActionTime';                     Type = 'datetime' }
                @{ Name = 'ActionType';                     Type = 'string' }
                @{ Name = 'MachineId';                      Type = 'string' }
                @{ Name = 'MachineName';                    Type = 'string' }
                @{ Name = 'FileName';                       Type = 'string' }
                @{ Name = 'FolderPath';                     Type = 'string' }
                @{ Name = 'FileSha1';                       Type = 'string' }
                @{ Name = 'FileSha256';                     Type = 'string' }
                @{ Name = 'InitiatingProcessId';            Type = 'int' }
                @{ Name = 'InitiatingProcessFileName';      Type = 'string' }
                @{ Name = 'InitiatingProcessCommandLine';   Type = 'string' }
                @{ Name = 'InitiatingProcessAccountName';   Type = 'string' }
                @{ Name = 'ReportId';                       Type = 'long' }
                @{ Name = 'SourceProvider';                 Type = 'string' }
                @{ Name = 'Event';                          Type = 'dynamic' }
            )
            ColumnMappings = @(
                @{ Column = 'ActionTime';                   Properties = @{ Path = '$.ActionTime' } }
                @{ Column = 'ActionType';                   Properties = @{ Path = '$.ActionType' } }
                @{ Column = 'MachineId';                    Properties = @{ Path = '$.Machine.MachineId' } }
                @{ Column = 'MachineName';                  Properties = @{ Path = '$.Machine.Name' } }
                @{ Column = 'FileName';                     Properties = @{ Path = '$.File.FileName' } }
                @{ Column = 'FolderPath';                   Properties = @{ Path = '$.File.FolderPath' } }
                @{ Column = 'FileSha1';                     Properties = @{ Path = '$.File.Sha1' } }
                @{ Column = 'FileSha256';                   Properties = @{ Path = '$.File.Sha256' } }
                @{ Column = 'InitiatingProcessId';          Properties = @{ Path = '$.InitiatingProcess.Id' } }
                @{ Column = 'InitiatingProcessFileName';    Properties = @{ Path = '$.InitiatingProcess.ImageFile.FileName' } }
                @{ Column = 'InitiatingProcessCommandLine'; Properties = @{ Path = '$.InitiatingProcess.CommandLine' } }
                @{ Column = 'InitiatingProcessAccountName'; Properties = @{ Path = '$.InitiatingProcess.User.AccountName' } }
                @{ Column = 'ReportId';                     Properties = @{ Path = '$.ReportId' } }
                @{ Column = 'SourceProvider';               Properties = @{ Path = '$.SourceProvider' } }
                @{ Column = 'Event';                        Properties = @{ Path = '$' } }
            )
        }

        XDRDeviceTimelineNetworkEvents = @{
            TableName     = 'XDRDeviceTimelineNetworkEvents'
            Source        = 'DeviceTimeline'
            RoutingField  = 'ActionType'
            RoutingValues = @(
                'ConnectionRequest'
                'ConnectionSuccess'
                'ConnectionFailed'
                'ConnectionAcknowledged'
                'InboundConnectionAccepted'
                'NetworkSignatureInspected'
            )
            Columns = @(
                @{ Name = 'ActionTime';                     Type = 'datetime' }
                @{ Name = 'ActionType';                     Type = 'string' }
                @{ Name = 'MachineId';                      Type = 'string' }
                @{ Name = 'MachineName';                    Type = 'string' }
                @{ Name = 'LocalIP';                        Type = 'string' }
                @{ Name = 'LocalPort';                      Type = 'int' }
                @{ Name = 'RemoteIP';                       Type = 'string' }
                @{ Name = 'RemotePort';                     Type = 'int' }
                @{ Name = 'Protocol';                       Type = 'string' }
                @{ Name = 'RemoteUrl';                      Type = 'string' }
                @{ Name = 'InitiatingProcessId';            Type = 'int' }
                @{ Name = 'InitiatingProcessFileName';      Type = 'string' }
                @{ Name = 'InitiatingProcessCommandLine';   Type = 'string' }
                @{ Name = 'InitiatingProcessAccountName';   Type = 'string' }
                @{ Name = 'ReportId';                       Type = 'long' }
                @{ Name = 'SourceProvider';                 Type = 'string' }
                @{ Name = 'Event';                          Type = 'dynamic' }
            )
            ColumnMappings = @(
                @{ Column = 'ActionTime';                   Properties = @{ Path = '$.ActionTime' } }
                @{ Column = 'ActionType';                   Properties = @{ Path = '$.ActionType' } }
                @{ Column = 'MachineId';                    Properties = @{ Path = '$.Machine.MachineId' } }
                @{ Column = 'MachineName';                  Properties = @{ Path = '$.Machine.Name' } }
                @{ Column = 'LocalIP';                      Properties = @{ Path = '$.LocalEndpoint.IPAddress' } }
                @{ Column = 'LocalPort';                    Properties = @{ Path = '$.LocalEndpoint.Port' } }
                @{ Column = 'RemoteIP';                     Properties = @{ Path = '$.RemoteEndpoint.IPAddress' } }
                @{ Column = 'RemotePort';                   Properties = @{ Path = '$.RemoteEndpoint.Port' } }
                @{ Column = 'Protocol';                     Properties = @{ Path = '$.RemoteEndpoint.Protocol' } }
                @{ Column = 'RemoteUrl';                    Properties = @{ Path = '$.RemoteEndpoint.Url' } }
                @{ Column = 'InitiatingProcessId';          Properties = @{ Path = '$.InitiatingProcess.Id' } }
                @{ Column = 'InitiatingProcessFileName';    Properties = @{ Path = '$.InitiatingProcess.ImageFile.FileName' } }
                @{ Column = 'InitiatingProcessCommandLine'; Properties = @{ Path = '$.InitiatingProcess.CommandLine' } }
                @{ Column = 'InitiatingProcessAccountName'; Properties = @{ Path = '$.InitiatingProcess.User.AccountName' } }
                @{ Column = 'ReportId';                     Properties = @{ Path = '$.ReportId' } }
                @{ Column = 'SourceProvider';               Properties = @{ Path = '$.SourceProvider' } }
                @{ Column = 'Event';                        Properties = @{ Path = '$' } }
            )
        }

        XDRDeviceTimelineRegistryEvents = @{
            TableName     = 'XDRDeviceTimelineRegistryEvents'
            Source        = 'DeviceTimeline'
            RoutingField  = 'ActionType'
            RoutingValues = @(
                'RegistryValueSet'
                'RegistryKeyCreated'
                'RegistryKeyDeleted'
                'RegistryValueDeleted'
            )
            Columns = @(
                @{ Name = 'ActionTime';                     Type = 'datetime' }
                @{ Name = 'ActionType';                     Type = 'string' }
                @{ Name = 'MachineId';                      Type = 'string' }
                @{ Name = 'MachineName';                    Type = 'string' }
                @{ Name = 'RegistryKey';                    Type = 'string' }
                @{ Name = 'RegistryValueName';              Type = 'string' }
                @{ Name = 'RegistryValueData';              Type = 'string' }
                @{ Name = 'RegistryValueType';              Type = 'string' }
                @{ Name = 'PreviousRegistryKey';            Type = 'string' }
                @{ Name = 'PreviousRegistryValueName';      Type = 'string' }
                @{ Name = 'PreviousRegistryValueData';      Type = 'string' }
                @{ Name = 'InitiatingProcessId';            Type = 'int' }
                @{ Name = 'InitiatingProcessFileName';      Type = 'string' }
                @{ Name = 'InitiatingProcessCommandLine';   Type = 'string' }
                @{ Name = 'InitiatingProcessAccountName';   Type = 'string' }
                @{ Name = 'ReportId';                       Type = 'long' }
                @{ Name = 'SourceProvider';                 Type = 'string' }
                @{ Name = 'Event';                          Type = 'dynamic' }
            )
            ColumnMappings = @(
                @{ Column = 'ActionTime';                   Properties = @{ Path = '$.ActionTime' } }
                @{ Column = 'ActionType';                   Properties = @{ Path = '$.ActionType' } }
                @{ Column = 'MachineId';                    Properties = @{ Path = '$.Machine.MachineId' } }
                @{ Column = 'MachineName';                  Properties = @{ Path = '$.Machine.Name' } }
                @{ Column = 'RegistryKey';                  Properties = @{ Path = '$.Registry.Key' } }
                @{ Column = 'RegistryValueName';            Properties = @{ Path = '$.Registry.ValueName' } }
                @{ Column = 'RegistryValueData';            Properties = @{ Path = '$.Registry.ValueData' } }
                @{ Column = 'RegistryValueType';            Properties = @{ Path = '$.Registry.ValueType' } }
                @{ Column = 'PreviousRegistryKey';          Properties = @{ Path = '$.PreviousRegistry.Key' } }
                @{ Column = 'PreviousRegistryValueName';    Properties = @{ Path = '$.PreviousRegistry.ValueName' } }
                @{ Column = 'PreviousRegistryValueData';    Properties = @{ Path = '$.PreviousRegistry.ValueData' } }
                @{ Column = 'InitiatingProcessId';          Properties = @{ Path = '$.InitiatingProcess.Id' } }
                @{ Column = 'InitiatingProcessFileName';    Properties = @{ Path = '$.InitiatingProcess.ImageFile.FileName' } }
                @{ Column = 'InitiatingProcessCommandLine'; Properties = @{ Path = '$.InitiatingProcess.CommandLine' } }
                @{ Column = 'InitiatingProcessAccountName'; Properties = @{ Path = '$.InitiatingProcess.User.AccountName' } }
                @{ Column = 'ReportId';                     Properties = @{ Path = '$.ReportId' } }
                @{ Column = 'SourceProvider';               Properties = @{ Path = '$.SourceProvider' } }
                @{ Column = 'Event';                        Properties = @{ Path = '$' } }
            )
        }

        XDRDeviceTimelineLogonEvents = @{
            TableName     = 'XDRDeviceTimelineLogonEvents'
            Source        = 'DeviceTimeline'
            RoutingField  = 'ActionType'
            RoutingValues = @(
                'LogonSuccess'
                'LogonFailed'
            )
            Columns = @(
                @{ Name = 'ActionTime';                Type = 'datetime' }
                @{ Name = 'ActionType';                Type = 'string' }
                @{ Name = 'MachineId';                 Type = 'string' }
                @{ Name = 'MachineName';               Type = 'string' }
                @{ Name = 'AccountName';               Type = 'string' }
                @{ Name = 'AccountDomain';             Type = 'string' }
                @{ Name = 'AccountSid';                Type = 'string' }
                @{ Name = 'LogonType';                 Type = 'string' }
                @{ Name = 'RemoteIP';                  Type = 'string' }
                @{ Name = 'RemoteMachineName';         Type = 'string' }
                @{ Name = 'RemoteMachineDomain';       Type = 'string' }
                @{ Name = 'InitiatingProcessId';       Type = 'int' }
                @{ Name = 'InitiatingProcessFileName'; Type = 'string' }
                @{ Name = 'ReportId';                  Type = 'long' }
                @{ Name = 'SourceProvider';            Type = 'string' }
                @{ Name = 'Event';                     Type = 'dynamic' }
            )
            ColumnMappings = @(
                @{ Column = 'ActionTime';                Properties = @{ Path = '$.ActionTime' } }
                @{ Column = 'ActionType';                Properties = @{ Path = '$.ActionType' } }
                @{ Column = 'MachineId';                 Properties = @{ Path = '$.Machine.MachineId' } }
                @{ Column = 'MachineName';               Properties = @{ Path = '$.Machine.Name' } }
                @{ Column = 'AccountName';               Properties = @{ Path = '$.User.AccountName' } }
                @{ Column = 'AccountDomain';             Properties = @{ Path = '$.User.AccountDomainName' } }
                @{ Column = 'AccountSid';                Properties = @{ Path = '$.User.AccountSid' } }
                @{ Column = 'LogonType';                 Properties = @{ Path = '$.LogonType' } }
                @{ Column = 'RemoteIP';                  Properties = @{ Path = '$.RemoteEndpoint.IPAddress' } }
                @{ Column = 'RemoteMachineName';         Properties = @{ Path = '$.RemoteMachine.Name' } }
                @{ Column = 'RemoteMachineDomain';       Properties = @{ Path = '$.RemoteMachine.Domain' } }
                @{ Column = 'InitiatingProcessId';       Properties = @{ Path = '$.InitiatingProcess.Id' } }
                @{ Column = 'InitiatingProcessFileName'; Properties = @{ Path = '$.InitiatingProcess.ImageFile.FileName' } }
                @{ Column = 'ReportId';                  Properties = @{ Path = '$.ReportId' } }
                @{ Column = 'SourceProvider';            Properties = @{ Path = '$.SourceProvider' } }
                @{ Column = 'Event';                     Properties = @{ Path = '$' } }
            )
        }

        XDRDeviceTimelineAlertEvents = @{
            TableName     = 'XDRDeviceTimelineAlertEvents'
            Source        = 'DeviceTimeline'
            RoutingField  = 'ActionType'
            RoutingValues = @('OneCyber')
            Columns = @(
                @{ Name = 'ActionTime';                     Type = 'datetime' }
                @{ Name = 'ActionType';                     Type = 'string' }
                @{ Name = 'MachineId';                      Type = 'string' }
                @{ Name = 'MachineName';                    Type = 'string' }
                @{ Name = 'Description';                    Type = 'string' }
                @{ Name = 'CyberActionTypeName';            Type = 'string' }
                @{ Name = 'RelatedObservationName';         Type = 'string' }
                @{ Name = 'InitiatingProcessFileName';      Type = 'string' }
                @{ Name = 'InitiatingProcessCommandLine';   Type = 'string' }
                @{ Name = 'AccountName';                    Type = 'string' }
                @{ Name = 'AccountDomain';                  Type = 'string' }
                @{ Name = 'ReportId';                       Type = 'long' }
                @{ Name = 'SourceProvider';                 Type = 'string' }
                @{ Name = 'IsCyberData';                    Type = 'bool' }
                @{ Name = 'Event';                          Type = 'dynamic' }
            )
            ColumnMappings = @(
                @{ Column = 'ActionTime';                   Properties = @{ Path = '$.ActionTime' } }
                @{ Column = 'ActionType';                   Properties = @{ Path = '$.ActionType' } }
                @{ Column = 'MachineId';                    Properties = @{ Path = '$.Machine.MachineId' } }
                @{ Column = 'MachineName';                  Properties = @{ Path = '$.Machine.Name' } }
                @{ Column = 'Description';                  Properties = @{ Path = '$.Description' } }
                @{ Column = 'CyberActionTypeName';          Properties = @{ Path = '$.CyberActionType.TypeName' } }
                @{ Column = 'RelatedObservationName';       Properties = @{ Path = '$.RelatedObservationName' } }
                @{ Column = 'InitiatingProcessFileName';    Properties = @{ Path = '$.InitiatingProcess.ImageFile.FileName' } }
                @{ Column = 'InitiatingProcessCommandLine'; Properties = @{ Path = '$.InitiatingProcess.CommandLine' } }
                @{ Column = 'AccountName';                  Properties = @{ Path = '$.User.AccountName' } }
                @{ Column = 'AccountDomain';                Properties = @{ Path = '$.User.AccountDomainName' } }
                @{ Column = 'ReportId';                     Properties = @{ Path = '$.ReportId' } }
                @{ Column = 'SourceProvider';               Properties = @{ Path = '$.SourceProvider' } }
                @{ Column = 'IsCyberData';                  Properties = @{ Path = '$.IsCyberData' } }
                @{ Column = 'Event';                        Properties = @{ Path = '$' } }
            )
        }

        XDRDeviceTimelineOtherEvents = @{
            TableName     = 'XDRDeviceTimelineOtherEvents'
            Source        = 'DeviceTimeline'
            RoutingField  = 'ActionType'
            RoutingValues = @()
            Columns = @(
                @{ Name = 'ActionTime';      Type = 'datetime' }
                @{ Name = 'ActionType';      Type = 'string' }
                @{ Name = 'MachineId';       Type = 'string' }
                @{ Name = 'MachineName';     Type = 'string' }
                @{ Name = 'ReportId';        Type = 'long' }
                @{ Name = 'SourceProvider';  Type = 'string' }
                @{ Name = 'Event';           Type = 'dynamic' }
            )
            ColumnMappings = @(
                @{ Column = 'ActionTime';     Properties = @{ Path = '$.ActionTime' } }
                @{ Column = 'ActionType';     Properties = @{ Path = '$.ActionType' } }
                @{ Column = 'MachineId';      Properties = @{ Path = '$.Machine.MachineId' } }
                @{ Column = 'MachineName';    Properties = @{ Path = '$.Machine.Name' } }
                @{ Column = 'ReportId';       Properties = @{ Path = '$.ReportId' } }
                @{ Column = 'SourceProvider'; Properties = @{ Path = '$.SourceProvider' } }
                @{ Column = 'Event';          Properties = @{ Path = '$' } }
            )
        }

        # endregion

        # region Identity Timeline Tables (Source = 'IdentityTimeline', RoutingField = 'SourceTable')

        XDRIdentityTimelineCloudAppEvents = @{
            TableName     = 'XDRIdentityTimelineCloudAppEvents'
            Source        = 'IdentityTimeline'
            RoutingField  = 'SourceTable'
            RoutingValues = @('CloudAppEvents')
            Columns = @(
                @{ Name = 'Timestamp';     Type = 'datetime' }
                @{ Name = 'ActionType';    Type = 'string' }
                @{ Name = 'ActivityType';  Type = 'string' }
                @{ Name = 'Application';   Type = 'string' }
                @{ Name = 'ApplicationId'; Type = 'int' }
                @{ Name = 'Location';      Type = 'string' }
                @{ Name = 'Ip';            Type = 'string' }
                @{ Name = 'Description';   Type = 'string' }
                @{ Name = 'Aad';           Type = 'string' }
                @{ Name = 'EventId';       Type = 'string' }
                @{ Name = 'Event';         Type = 'dynamic' }
            )
            ColumnMappings = @(
                @{ Column = 'Timestamp';     Properties = @{ Path = '$.Timestamp' } }
                @{ Column = 'ActionType';    Properties = @{ Path = '$.ActionType' } }
                @{ Column = 'ActivityType';  Properties = @{ Path = '$.ActivityType' } }
                @{ Column = 'Application';   Properties = @{ Path = '$.Application' } }
                @{ Column = 'ApplicationId'; Properties = @{ Path = '$.ApplicationId' } }
                @{ Column = 'Location';      Properties = @{ Path = '$.Location' } }
                @{ Column = 'Ip';            Properties = @{ Path = '$.Ip' } }
                @{ Column = 'Description';   Properties = @{ Path = '$.Description' } }
                @{ Column = 'Aad';           Properties = @{ Path = '$.Aad' } }
                @{ Column = 'EventId';       Properties = @{ Path = '$.EventId' } }
                @{ Column = 'Event';         Properties = @{ Path = '$' } }
            )
        }

        XDRIdentityTimelineSignInEvents = @{
            TableName     = 'XDRIdentityTimelineSignInEvents'
            Source        = 'IdentityTimeline'
            RoutingField  = 'SourceTable'
            RoutingValues = @('SignInEvents')
            Columns = @(
                @{ Name = 'Timestamp';     Type = 'datetime' }
                @{ Name = 'ActionType';    Type = 'string' }
                @{ Name = 'Ip';            Type = 'string' }
                @{ Name = 'Location';      Type = 'string' }
                @{ Name = 'FailureReason'; Type = 'string' }
                @{ Name = 'RiskState';     Type = 'string' }
                @{ Name = 'DeviceName';    Type = 'string' }
                @{ Name = 'Aad';           Type = 'string' }
                @{ Name = 'EventId';       Type = 'string' }
                @{ Name = 'ReportId';      Type = 'string' }
                @{ Name = 'Event';         Type = 'dynamic' }
            )
            ColumnMappings = @(
                @{ Column = 'Timestamp';     Properties = @{ Path = '$.Timestamp' } }
                @{ Column = 'ActionType';    Properties = @{ Path = '$.ActionType' } }
                @{ Column = 'Ip';            Properties = @{ Path = '$.Ip' } }
                @{ Column = 'Location';      Properties = @{ Path = '$.Location' } }
                @{ Column = 'FailureReason'; Properties = @{ Path = '$.FailureReason' } }
                @{ Column = 'RiskState';     Properties = @{ Path = '$.RiskState' } }
                @{ Column = 'DeviceName';    Properties = @{ Path = '$.DeviceName' } }
                @{ Column = 'Aad';           Properties = @{ Path = '$.Aad' } }
                @{ Column = 'EventId';       Properties = @{ Path = '$.EventId' } }
                @{ Column = 'ReportId';      Properties = @{ Path = '$.ReportId' } }
                @{ Column = 'Event';         Properties = @{ Path = '$' } }
            )
        }

        XDRIdentityTimelineAlerts = @{
            TableName     = 'XDRIdentityTimelineAlerts'
            Source        = 'IdentityTimeline'
            RoutingField  = 'SourceTable'
            RoutingValues = @('Alerts')
            Columns = @(
                @{ Name = 'Timestamp';        Type = 'datetime' }
                @{ Name = 'AlertId';          Type = 'string' }
                @{ Name = 'Title';            Type = 'string' }
                @{ Name = 'Severity';         Type = 'string' }
                @{ Name = 'Status';           Type = 'string' }
                @{ Name = 'Description';      Type = 'string' }
                @{ Name = 'ServiceSource';    Type = 'string' }
                @{ Name = 'MitreTechniques'; Type = 'string' }
                @{ Name = 'Aad';              Type = 'string' }
                @{ Name = 'Sid';              Type = 'string' }
                @{ Name = 'Event';            Type = 'dynamic' }
            )
            ColumnMappings = @(
                @{ Column = 'Timestamp';        Properties = @{ Path = '$.Timestamp' } }
                @{ Column = 'AlertId';          Properties = @{ Path = '$.AlertId' } }
                @{ Column = 'Title';            Properties = @{ Path = '$.Title' } }
                @{ Column = 'Severity';         Properties = @{ Path = '$.Severity' } }
                @{ Column = 'Status';           Properties = @{ Path = '$.Status' } }
                @{ Column = 'Description';      Properties = @{ Path = '$.Description' } }
                @{ Column = 'ServiceSource';    Properties = @{ Path = '$.ServiceSource' } }
                @{ Column = 'MitreTechniques'; Properties = @{ Path = '$.MitreTechniques' } }
                @{ Column = 'Aad';              Properties = @{ Path = '$.Aad' } }
                @{ Column = 'Sid';              Properties = @{ Path = '$.Sid' } }
                @{ Column = 'Event';            Properties = @{ Path = '$' } }
            )
        }

        # endregion

        # region Cloud Apps Tables

        XDRCloudAppsActivityTimeline = @{
            TableName     = 'XDRCloudAppsActivityTimeline'
            Source        = 'CloudAppsActivityTimeline'
            RoutingField  = $null
            RoutingValues = @()
            Columns = @(
                @{ Name = 'Date';         Type = 'datetime' }
                @{ Name = 'Timestamp';    Type = 'long' }
                @{ Name = 'ActivityId';   Type = 'string' }
                @{ Name = 'RecordId';     Type = 'string' }
                @{ Name = 'UserName';     Type = 'string' }
                @{ Name = 'User';         Type = 'string' }
                @{ Name = 'Account';      Type = 'string' }
                @{ Name = 'AppName';      Type = 'string' }
                @{ Name = 'App';          Type = 'string' }
                @{ Name = 'Service';      Type = 'string' }
                @{ Name = 'ActivityType'; Type = 'string' }
                @{ Name = 'EventType';    Type = 'string' }
                @{ Name = 'Action';       Type = 'string' }
                @{ Name = 'IpAddress';    Type = 'string' }
                @{ Name = 'Ip';           Type = 'string' }
                @{ Name = 'Location';     Type = 'string' }
                @{ Name = 'Country';      Type = 'string' }
                @{ Name = 'Event';        Type = 'dynamic' }
            )
            ColumnMappings = @(
                @{ Column = 'Date';         Properties = @{ Path = '$.timestamp'; Transform = 'DateTimeFromUnixMilliseconds' } }
                @{ Column = 'Timestamp';    Properties = @{ Path = '$.timestamp' } }
                @{ Column = 'ActivityId';   Properties = @{ Path = '$._id' } }
                @{ Column = 'RecordId';     Properties = @{ Path = '$.uid' } }
                @{ Column = 'UserName';     Properties = @{ Path = '$.user.userName' } }
                @{ Column = 'User';         Properties = @{ Path = '$.user.userName' } }
                @{ Column = 'Account';      Properties = @{ Path = '$.resolvedActor.id' } }
                @{ Column = 'AppName';      Properties = @{ Path = '$.rawDataJson.ApplicationName' } }
                @{ Column = 'App';          Properties = @{ Path = '$.appId' } }
                @{ Column = 'Service';      Properties = @{ Path = '$.rawDataJson.Workload' } }
                @{ Column = 'ActivityType'; Properties = @{ Path = '$.mainInfo.prettyOperationName' } }
                @{ Column = 'EventType';    Properties = @{ Path = '$.eventTypeName' } }
                @{ Column = 'Action';       Properties = @{ Path = '$.mainInfo.rawOperationName' } }
                @{ Column = 'IpAddress';    Properties = @{ Path = '$.device.clientIP' } }
                @{ Column = 'Ip';           Properties = @{ Path = '$.rawDataJson.IpAddress' } }
                @{ Column = 'Location';     Properties = @{ Path = '$.location.city' } }
                @{ Column = 'Country';      Properties = @{ Path = '$.location.countryCode' } }
                @{ Column = 'Event';        Properties = @{ Path = '$' } }
            )
        }

        # endregion

        # region Standalone Tables

        XDRAlerts = @{
            TableName     = 'XDRAlerts'
            Source        = 'Alert'
            RoutingField  = $null
            RoutingValues = @()
            Columns = @(
                @{ Name = 'alertId';              Type = 'string' }
                @{ Name = 'alertDisplayName';     Type = 'string' }
                @{ Name = 'severity';             Type = 'string' }
                @{ Name = 'status';               Type = 'string' }
                @{ Name = 'classification';       Type = 'string' }
                @{ Name = 'determination';        Type = 'string' }
                @{ Name = 'providerName';         Type = 'string' }
                @{ Name = 'detectionSource';      Type = 'string' }
                @{ Name = 'category';             Type = 'string' }
                @{ Name = 'incidentId';           Type = 'string' }
                @{ Name = 'startTimeUtc';         Type = 'datetime' }
                @{ Name = 'endTimeUtc';           Type = 'datetime' }
                @{ Name = 'timeGenerated';        Type = 'datetime' }
                @{ Name = 'mitreAttackCategory';  Type = 'string' }
                @{ Name = 'mitreAttackTechnique'; Type = 'string' }
                @{ Name = 'description';          Type = 'string' }
                @{ Name = 'Event';                Type = 'dynamic' }
            )
            ColumnMappings = @(
                @{ Column = 'alertId';              Properties = @{ Path = '$.alertId' } }
                @{ Column = 'alertDisplayName';     Properties = @{ Path = '$.alertDisplayName' } }
                @{ Column = 'severity';             Properties = @{ Path = '$.severity' } }
                @{ Column = 'status';               Properties = @{ Path = '$.status' } }
                @{ Column = 'classification';       Properties = @{ Path = '$.classification' } }
                @{ Column = 'determination';        Properties = @{ Path = '$.determination' } }
                @{ Column = 'providerName';         Properties = @{ Path = '$.providerName' } }
                @{ Column = 'detectionSource';      Properties = @{ Path = '$.detectionSource' } }
                @{ Column = 'category';             Properties = @{ Path = '$.category' } }
                @{ Column = 'incidentId';           Properties = @{ Path = '$.incidentId' } }
                @{ Column = 'startTimeUtc';         Properties = @{ Path = '$.startTimeUtc' } }
                @{ Column = 'endTimeUtc';           Properties = @{ Path = '$.endTimeUtc' } }
                @{ Column = 'timeGenerated';        Properties = @{ Path = '$.timeGenerated' } }
                @{ Column = 'mitreAttackCategory';  Properties = @{ Path = '$.mitreAttackCategory' } }
                @{ Column = 'mitreAttackTechnique'; Properties = @{ Path = '$.mitreAttackTechnique' } }
                @{ Column = 'description';          Properties = @{ Path = '$.description' } }
                @{ Column = 'Event';                Properties = @{ Path = '$' } }
            )
        }

        XDRIncidents = @{
            TableName     = 'XDRIncidents'
            Source        = 'Incident'
            RoutingField  = $null
            RoutingValues = @()
            Columns = @(
                @{ Name = 'IncidentId';           Type = 'int' }
                @{ Name = 'Title';                Type = 'string' }
                @{ Name = 'Severity';             Type = 'int' }
                @{ Name = 'SeverityName';         Type = 'string' }
                @{ Name = 'Status';               Type = 'int' }
                @{ Name = 'Classification';       Type = 'int' }
                @{ Name = 'Determination';        Type = 'int' }
                @{ Name = 'AlertCount';           Type = 'int' }
                @{ Name = 'CreatedTime';          Type = 'datetime' }
                @{ Name = 'LastEventTime';        Type = 'datetime' }
                @{ Name = 'FirstEventTime';       Type = 'datetime' }
                @{ Name = 'ComputerDnsName';      Type = 'string' }
                @{ Name = 'AccountName';          Type = 'string' }
                @{ Name = 'Description';          Type = 'string' }
                @{ Name = 'DetectionSourceNames'; Type = 'string' }
                @{ Name = 'Event';                Type = 'dynamic' }
            )
            ColumnMappings = @(
                @{ Column = 'IncidentId';           Properties = @{ Path = '$.IncidentId' } }
                @{ Column = 'Title';                Properties = @{ Path = '$.Title' } }
                @{ Column = 'Severity';             Properties = @{ Path = '$.Severity' } }
                @{ Column = 'SeverityName';         Properties = @{ Path = '$.SeverityName' } }
                @{ Column = 'Status';               Properties = @{ Path = '$.Status' } }
                @{ Column = 'Classification';       Properties = @{ Path = '$.Classification' } }
                @{ Column = 'Determination';        Properties = @{ Path = '$.Determination' } }
                @{ Column = 'AlertCount';           Properties = @{ Path = '$.AlertCount' } }
                @{ Column = 'CreatedTime';          Properties = @{ Path = '$.CreatedTime' } }
                @{ Column = 'LastEventTime';        Properties = @{ Path = '$.LastEventTime' } }
                @{ Column = 'FirstEventTime';       Properties = @{ Path = '$.FirstEventTime' } }
                @{ Column = 'ComputerDnsName';      Properties = @{ Path = '$.ComputerDnsName' } }
                @{ Column = 'AccountName';          Properties = @{ Path = '$.AccountName' } }
                @{ Column = 'Description';          Properties = @{ Path = '$.Description' } }
                @{ Column = 'DetectionSourceNames'; Properties = @{ Path = '$.DetectionSourceNames' } }
                @{ Column = 'Event';                Properties = @{ Path = '$' } }
            )
        }

        XDRDevices = @{
            TableName     = 'XDRDevices'
            Source        = 'Device'
            RoutingField  = $null
            RoutingValues = @()
            Columns = @(
                @{ Name = 'MachineId';        Type = 'string' }
                @{ Name = 'ComputerDnsName';  Type = 'string' }
                @{ Name = 'OsPlatform';       Type = 'string' }
                @{ Name = 'HealthStatus';     Type = 'string' }
                @{ Name = 'RiskScore';        Type = 'string' }
                @{ Name = 'ExposureScore';    Type = 'string' }
                @{ Name = 'LastIpAddress';    Type = 'string' }
                @{ Name = 'LastSeen';         Type = 'datetime' }
                @{ Name = 'FirstSeen';        Type = 'datetime' }
                @{ Name = 'DeviceCategory';   Type = 'string' }
                @{ Name = 'DeviceType';       Type = 'string' }
                @{ Name = 'OnboardingStatus'; Type = 'string' }
                @{ Name = 'Event';            Type = 'dynamic' }
            )
            ColumnMappings = @(
                @{ Column = 'MachineId';        Properties = @{ Path = '$.MachineId' } }
                @{ Column = 'ComputerDnsName';  Properties = @{ Path = '$.ComputerDnsName' } }
                @{ Column = 'OsPlatform';       Properties = @{ Path = '$.OsPlatform' } }
                @{ Column = 'HealthStatus';     Properties = @{ Path = '$.HealthStatus' } }
                @{ Column = 'RiskScore';        Properties = @{ Path = '$.RiskScore' } }
                @{ Column = 'ExposureScore';    Properties = @{ Path = '$.ExposureScore' } }
                @{ Column = 'LastIpAddress';    Properties = @{ Path = '$.LastIpAddress' } }
                @{ Column = 'LastSeen';         Properties = @{ Path = '$.LastSeen' } }
                @{ Column = 'FirstSeen';        Properties = @{ Path = '$.FirstSeen' } }
                @{ Column = 'DeviceCategory';   Properties = @{ Path = '$.DeviceCategory' } }
                @{ Column = 'DeviceType';       Properties = @{ Path = '$.DeviceType' } }
                @{ Column = 'OnboardingStatus'; Properties = @{ Path = '$.OnboardingStatus' } }
                @{ Column = 'Event';            Properties = @{ Path = '$' } }
            )
        }

        # endregion

        # region Advanced Hunting

        XDRAdvancedHuntingResults = @{
            TableName     = 'XDRAdvancedHuntingResults'
            Source        = 'AdvancedHunting'
            RoutingField  = $null
            RoutingValues = @()
            Columns = @(
                @{ Name = 'QueryTimestamp'; Type = 'datetime' }
                @{ Name = 'Event';          Type = 'dynamic' }
            )
            ColumnMappings = @(
                @{ Column = 'QueryTimestamp'; Properties = @{ Path = '$.QueryTimestamp' } }
                @{ Column = 'Event';          Properties = @{ Path = '$' } }
            )
        }

        # endregion
    }
}

function Resolve-XdrAzureDataExplorerTableProfile {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$Source,

        [Parameter(Mandatory)]
        [object]$InputEvent
    )

    $resolvedSource = switch ($Source) {
        'CloudAppsTimeline' { 'CloudAppsActivityTimeline' }
        default { $Source }
    }

    $profiles = Get-XdrAzureDataExplorerTableProfile
    $sourceProfiles = @($profiles.Values | Where-Object { $_.Source -eq $resolvedSource })

    if ($sourceProfiles.Count -eq 0) {
        Write-Verbose "No table profiles found for source '$resolvedSource'"
        return $null
    }

    # Standalone tables have no routing field — return the single profile directly
    $routed = @($sourceProfiles | Where-Object { $_.RoutingField })
    if ($routed.Count -eq 0) {
        return $sourceProfiles[0]
    }

    # Determine the routing value from the event
    $routingField = $routed[0].RoutingField
    $routingValue = $InputEvent.$routingField
    Write-Verbose "Routing '$resolvedSource' event by $routingField = '$routingValue'"

    # Find the profile whose RoutingValues contains the routing value
    foreach ($tableProfile in $routed) {
        if ($tableProfile.RoutingValues -contains $routingValue) {
            return $tableProfile
        }
    }

    # Check for a catch-all profile (empty RoutingValues)
    $catchAll = $routed | Where-Object { $_.RoutingValues.Count -eq 0 }
    if ($catchAll) {
        Write-Verbose "No specific profile matched '$routingValue' for source '$resolvedSource', using catch-all table '$($catchAll.TableName)'"
        return $catchAll
    }

    Write-Verbose "No table profile matched '$routingValue' for source '$resolvedSource'"
    return $null
}

function ConvertTo-XdrAzureDataExplorerTypedRecord {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)]
        [object]$InputEvent,

        [Parameter(Mandatory)]
        [hashtable]$TableProfile
    )

    $record = [ordered]@{}

    foreach ($mapping in $TableProfile.ColumnMappings) {
        $path = $mapping.Properties.Path

        # Full event reference — embed the original object
        if ($path -eq '$') {
            $record[$mapping.Column] = $InputEvent
            continue
        }

        # Walk the dotted path starting from the root object
        # Strip leading "$." prefix
        $segments = $path.Substring(2).Split('.')
        $value = $InputEvent
        foreach ($segment in $segments) {
            if ($null -eq $value) { break }
            $value = $value.$segment
        }

        if ($mapping.Properties.Transform -eq 'DateTimeFromUnixMilliseconds' -and $null -ne $value) {
            $value = [DateTimeOffset]::FromUnixTimeMilliseconds([long]$value).UtcDateTime
        }

        $record[$mapping.Column] = $value
    }

    return $record
}
