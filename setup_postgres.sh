echo "script to setup a postgres DB on localhost"

export DB_NAME=cloudtls
export DB_USER=cloud_tls

sudo -u postgres createuser --login --pwprompt $DB_USER
sudo -u postgres createdb --owner=$DB_USER $DB_NAME

echo "done!"
