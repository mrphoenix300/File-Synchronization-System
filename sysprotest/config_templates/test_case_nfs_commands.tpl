



## run a nfs_client (source) in another console  
## on SOURCE_CLIENT_IP
./nfs_client -p SOURCE_CLIENT_PORT

## run another nfs_client (target) in another console  
## on TARGET_CLIENT_IP 
./nfs_client -p TARGET_CLIENT_PORT

## run nfs_manager in aterm connected at NFS_MANAGER_IP and NFS_MANAGER_PORT
./nfs_manager -l np_nfs_manager.log -c sysprotest/config_nfs.cfg -n 5 -p NFS_MANAGER_PORT -b 7

## run nfs_console in another console 
./nfs_console -l np_nfs_console.log -h NFS_MANAGER_IP -p NFS_MANAGER_PORT

##check initial sync in target client

## console //
cancel /sysprotest/config_source_dir1 

## console
add /sysprotest/added_source_dir@SOURCE_CLIENT_IP:SOURCE_CLIENT_PORT /sysprotest/added_target_dir@TARGET_CLIENT_IP:TARGET_CLIENT_PORT
ls sysprotest/added_target_dir


## console //
shutdown

## Anoixe kai deixe ta log arxeio toy manager kai toy console


