# Task 1 Checkpoint 1

1. Install Apache

```text
sudo apt update
sudo apt install apache2
```

![](.gitbook/assets/step_1_apacheinstall.png)

2. Adjusting Firewall

Check existing firewall profiles and enable "Apache" firewall

![](.gitbook/assets/step_2_applist.png)

![](.gitbook/assets/step_2_ufwstat.png)

3. Check the status of the apache server if it is running or not.

![](.gitbook/assets/step_3_apachestat.png)

Map `localhost` to `appledora.lib` __by editing the `/etc/hosts` file

![](.gitbook/assets/step_3_map.png)

By visiting `appledora.lib` __the default apache webpage can be found.

![](.gitbook/assets/step_3_mapverify.png)

