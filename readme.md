<h1>Route 53 GUI</h1>

This is a small program for adding A record and CNAME to Route53 with out using the console or cli.
A record can be added with or with out PTR records if needed.
It may not be the best opdimized code for the job but it works for what I need it for.
there are places in the coded that need to be updated with the proper AWS varaibles

1. aws_access_key_id
2. aws_secret_access_key
3. HostedZoneId in the createawptr() funtion needs to have the reverse zone
