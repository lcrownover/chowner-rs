#!/bin/bash

TD=/opt/testdata

rm -rf /opt/testdata

# oneuser 84
# twouser 85
# threeuser 86
# oneusernew 87
# twousernew 88
# threeusernew 89

# --uidpair 84:87 --uidpair 85:88 --uidpair 86:89

useradd one
useradd oneuser
useradd twouser
useradd threeuser
useradd oneusernew
useradd twousernew
useradd threeusernew

mkdir -p $TD
mkdir -p $TD/shared/
chown oneuser $TD/shared/

mkdir -p $TD/one
echo "one data" | tee -a $TD/one/onefile
echo "one shared data" | tee -a $TD/shared/one
chown -R oneuser $TD/one/
chmod -R u=rwx,g=rwx $TD/one/
chown oneuser $TD/shared/one
setfacl -m u:oneuser:r $TD/shared/
setfacl -d -m u:oneuser:r $TD/shared/

mkdir -p $TD/two
echo "two data" | tee -a $TD/two/twofile
echo "two shared data" | tee -a $TD/shared/two
chown -R twouser $TD/two/
chmod -R u=rwx,g=rwx $TD/two/
chown twouser $TD/shared/two
setfacl -m u:twouser:r $TD/shared/
setfacl -d -m u:twouser:r $TD/shared/

mkdir -p $TD/three
echo "three data" | tee -a $TD/three/threefile
echo "three shared data" | tee -a $TD/shared/three
chown -R threeuser $TD/three/
chmod -R u=rwx,g=rwx $TD/three/
chown threeuser $TD/shared/three
setfacl -m u:threeuser:r $TD/shared/
setfacl -d -m u:threeuser:r $TD/shared/

rm -f $TD/one/shared-one
ln -s $TD/shared/one $TD/one/shared-one
