# MWC Pay Example

This example is a very simple web 1.0 PHP shopping site that demonstrates how to interface with the MWC Pay API to accept MimbleWimble Coin payments. A live version of this example is available [here](https://mwcwallet.com/mwc_pay_example).

### Nginx Instructions
The following commands can be ran from inside this directory to run this example locally as `http://mwcpayexample.local` if you're using Nginx as a web server.
```
echo "127.0.0.1 mwcpayexample.local" | sudo tee -a /etc/hosts
sudo ln -s `pwd` /srv/mwcpayexample.local
sudo ln -s /srv/mwcpayexample.local/nginx.conf /etc/nginx/sites-available/mwcpayexample.local.conf
sudo ln -s /etc/nginx/sites-available/mwcpayexample.local.conf /etc/nginx/sites-enabled/
sudo -u www-data php -S localhost:9012 callback.php
```

### Apache Instructions
The following commands can be ran from inside this directory to run this example locally as `http://mwcpayexample.local` if you're using Apache as a web server.
```
echo "127.0.0.1 mwcpayexample.local" | sudo tee -a /etc/hosts
sudo ln -s `pwd` /srv/mwcpayexample.local
sudo ln -s /srv/mwcpayexample.local/apache.conf /etc/apache2/sites-available/mwcpayexample.local.conf
sudo ln -s /etc/apache2/sites-available/mwcpayexample.local.conf /etc/apache2/sites-enabled/
sudo -u www-data php -S localhost:9012 callback.php
```
