#!/bin/bash



#################### SETUP PARAMS ###########################

NFS_MANAGER_IP="linux09.di.uoa.gr"
SOURCE_CLIENT_IP="linux10.di.uoa.gr"
TARGET_CLIENT_IP="linux11.di.uoa.gr"
NFS_MANAGER_PORT="5555"
SOURCE_CLIENT_PORT="5556"
TARGET_CLIENT_PORT="5557"
### the paths for hws to copy config and test files (at UOA linux)

# Καθαρισμός καταλόγων
rm -rf config_fss.cfg
rm -rf config_nfs.cfg
rm -rf ../config_fss.cfg
rm -rf ../config_nfs.cfg
rm -rf test_case_fss_commands.txt 
rm -rf test_case_nfs_commands.txt
rm -rf added_target_dir/*
rm -rf config_target_dir1/*
rm -rf config_target_dir2/*

# Απόλυτο μονοπάτι
FULLPATH=$(pwd)

########################### HW1 ###############################
###########################     ###############################

# Καθαρισμός κενών named pipes
find . -type p -size 0 -exec rm -v {} +

# fss config
CONFIG_FILE="config_templates/config_fss_template.tpl"
OUTPUT_FILE="config_fss.cfg"
sed "s#fullpathXXX#${FULLPATH}#g" "$CONFIG_FILE" > "$OUTPUT_FILE"



# fss test case
CONFIG_FILE="config_templates/test_case_fss_commands.tpl"
OUTPUT_FILE="test_case_fss_commands.txt"
sed "s#fullpathXXX#${FULLPATH}#g" "$CONFIG_FILE" > "$OUTPUT_FILE"

########################### HW2 ###############################
###########################     ###############################




CONFIG_FILE="config_templates/config_nfs_template.tpl"
OUTPUT_FILE="config_nfs.cfg"
# sed "s#fullpathXXX#${FULLPATH}#g" "$CONFIG_FILE" > "$OUTPUT_FILE"

sed -e "s#SOURCE_CLIENT_IP#${SOURCE_CLIENT_IP}#g" \
    -e "s#TARGET_CLIENT_IP#${TARGET_CLIENT_IP}#g" \
    -e "s#SOURCE_CLIENT_PORT#${SOURCE_CLIENT_PORT}#g" \
    -e "s#TARGET_CLIENT_PORT#${TARGET_CLIENT_PORT}#g" \
    "$CONFIG_FILE" > "$OUTPUT_FILE"


# nfs test case
CONFIG_FILE="config_templates/test_case_nfs_commands.tpl"
OUTPUT_FILE="test_case_nfs_commands.txt"
sed "s#fullpathXXX#${FULLPATH}#g" "$CONFIG_FILE" > "$OUTPUT_FILE"

sed -e "s#SOURCE_CLIENT_IP#${SOURCE_CLIENT_IP}#g" \
    -e "s#TARGET_CLIENT_IP#${TARGET_CLIENT_IP}#g" \
    -e "s#NFS_MANAGER_PORT#${NFS_MANAGER_PORT}#g" \
    -e "s#NFS_MANAGER_IP#${NFS_MANAGER_IP}#g" \
    -e "s#SOURCE_CLIENT_PORT#${SOURCE_CLIENT_PORT}#g" \
    -e "s#TARGET_CLIENT_PORT#${TARGET_CLIENT_PORT}#g" \
    "$CONFIG_FILE" > "$OUTPUT_FILE"


# Προαιρετική αντιγραφή στον πάνω φάκελο
mv config_fss.cfg ../
mv config_nfs.cfg ../
mv test_case_fss_commands.txt ../ 
mv test_case_nfs_commands.txt ../

exit 1
