
## run fss_manager in a term
./fss_manager -l np_fss_manager.log -c config_fss.cfg -n 5

## runn fss_console in another console
./fss_console -l np_fss_console.log

## check config file syncs
diff -r fullpathXXX/config_source_dir1 fullpathXXX/config_target_dir1
diff -r fullpathXXX/config_source_dir2 fullpathXXX/config_target_dir2

## console //prepei na epistrepsei oti parakoloutheite
status fullpathXXX/config_source_dir1

## console //
cancel fullpathXXX/config_source_dir1 

## console //prepei na epistrepsei oti DEN parakoloutheite
status fullpathXXX/config_source_dir1 

## console
add fullpathXXX/added_source_dir fullpathXXX/added_target_dir

##check add file syncs
diff -r fullpathXXX/added_source_dir fullpathXXX/added_target_dir

## console //status of added dir. prepei na epistrepsei oti  parakoloutheite
status fullpathXXX/added_source_dir 

## console //prepei na epistrepsei oti  parakoloutheite
sync fullpathXXX/config_source_dir2

#check updates replace sdi

#add a file
cp fullpathXXX/test_files/f4_1000.txt fullpathXXX/config_source_dir2 
ls -las fullpathXXX/config_target_dir2 

#add a file
cp fullpathXXX/test_files/f4_2000.txt fullpathXXX/config_source_dir2 
ls -las fullpathXXX/config_target_dir2

#remove a file
rm -rf fullpathXXX/config_source_dir2/f4_2000.txt
ls -las fullpathXXX/config_target_dir2

#update a file
ls -las fullpathXXX/config_source_dir2
cat fullpathXXX/test_files/f4_1000.txt >> fullpathXXX/config_source_dir2/f4_1000_copy.txt
ls -las fullpathXXX/config_target_dir2


## console //
shutdown

### fss script
##εμφανίζει όλους τους καταλόγους, την ημερομηνία και ώρα τελευταίου συγχρονισμού, μαζί με status
./fss_script.sh -p np_fss_manager.log -c listAll

##τους καταλόγους που παρακολουθούνται ενεργά.
./fss_script.sh -p np_fss_manager.log -c listMonitored
 
##τους καταλόγους που δεν παρακολουθούνται πλέον
./fss_script.sh -p np_fss_manager.log -c listStopped

##διαγράφει μόνο τον target κατάλογο ή το logfile
./fss_script.sh -p np_fss_manager.log -c purge ..... (oti exei ylopoihthei



## Anoixe kai deixe ta log arxeio toy manager kai toy console



