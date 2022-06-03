# Unit 19 Homework: Protecting VSI from Future Attacks


# Part 1: Windows Server Attack

Note to Ron: I will directly answer the specific questions at the end of each section.


## 1. Visualization of top signatures PRIOR to attack from Windows Server Logs

**We can see that top 3 signatures normally are:**
- “Special privileges assigned to the new logon”
- “A computer account was deleted”
- “A logon was attempted using explicit credentials”. 

**Search Queries:**

`source="windows_server_logs.csv" host=windows_server_logs | top limit=20 signature`

![signatures_baseline](https://raw.githubusercontent.com/yffenim/splunk_attack_visualizations/main/images/1_signatures_baseline.png)

---

## 2. Visualization of user baseline PRIOR to attack from Windows Server Logs

We can see that under normal circumstances, user distribution is generally even; there are not outliers or suspicious deviations. 

Note that I have removed the "OTHER" category as it was not visually semantic to our communication goals.

**Search Queries used:**

`source="windows_server_logs.csv" host=windows_server_logs | timechart count by user useother=f`

![user_baseline](https://raw.githubusercontent.com/yffenim/splunk_attack_visualizations/main/images/2_user_baseline.png)

---

## 3. Visualizing Data from Windows Attack Server Logs by Signature

**We can see that top 3 signatures during teh attack are:**
- "An attempt was made to reset an accounts password"
- "A user account was locked out"
- "An account was successfully logged on"

These 3 signatures are (1) different from baseline and (2) appearing in much higher volume than is expected on a normal day. (The forth top signature remains the same so we know we only need to focus on the top three.)

**Search Queries:** 

`source="windows_server_attack_logs.csv" host=windows_server_attack_logs | top limit=20 signature`

![attack_signatures](https://raw.githubusercontent.com/yffenim/splunk_attack_visualizations/main/images/3_attack_signatures.png)

---

## 4. Find the user accounts associated with high volumes of these three signatures:

**We can see that our focus needs to be on the following users connected to the following signatures:**
- user_k - An attempt was made to reset an accounts password
- user_a - A user account was locked out
- user_j - An account was succesfully logged on

![users_signatures_correlation](https://raw.githubusercontent.com/yffenim/splunk_attack_visualizations/main/images/4_1_users_signatures_correlation.png)

We can also check if we've missed any suspect users by viewing top users. This confirms that there are accounts to follow-up on:

![top_users](https://raw.githubusercontent.com/yffenim/splunk_attack_visualizations/main/images/4_2_top_users.png)

**Search Queries:**

Filter by user and signature, displaying field for accounts status: 

(Note to click on `count` after running query as we are interested in the top count)

`source="windows_server_attack_logs.csv" host="windows_server_attack_logs" | eval account_status=if(signature IN ("An attempt was made to reset an accounts password","A user account was locked out","An account was successfully logged on"), "Account Possibly Compromised", "Not Compromised") | top account_status by user, signature`

Confirm top users:
`source="windows_server_attack_logs.csv" host="windows_server_attack_logs"| top limit=10 user`

Another way to determine this would be to match the spike in user activity with the spike in signature activity by running the separate `timechart` queries and visually matching them on your dashboard. (I won't list the queries since the same syntax structure already been covered in 2.)


# Migitation Recommendations for Part I 

## Global Solution Password Security Strategies

1. The ideal solution is to implement **multi-factor authentication** to all company systems. This can be phone via software or hardware (yubikey).

2. If not MFA, another global solution is company-wide implementation of a password manager so that they can use complex passwords. (The problem with not using a password manager is that human brains struggle at memorizing random characters and the likelihood of a user writing down a complex password near their workstation is high, thereby defeating the purpose.)

3. If users will not install and use a password manager for complex passwords then asking users to create a long password of a random series of words would be sufficient. The password would be at least 20+ characters in length and the chosen words should not make a phrase since there are algorithmns that can predict common word connections. The words make it easy for a human brain to remember, thereby reducing the chances of a user writing it down and the length makes it difficult for a computer to guess. 

---

## 1. `user_k`: `An attempt was made to reset an accounts password`

Here is evidence of the brute force attack filtered specifically for `user_k`:

![user_k_signatures](https://raw.githubusercontent.com/yffenim/splunk_attack_visualizations/main/images/user_k_signatures.png)

Here is the same log with the the password reset attempt signature removed in order to see if anything else occured at the same time. Since there were no other actions associated with the account, we can conclude that they were not successfully hacked.

![user_k_signatures_II](https://raw.githubusercontent.com/yffenim/splunk_attack_visualizations/main/images/user_k_signatures_II.png)


### User Migitation Recommendations

The logs for `user_k` show that despite being a clear target in the attack, the attacker was not able to successfully logon or reset the account password.  We recommend checking in with this user to see if they noticed any usual activity to confirm what the logs suggest. For future mitigation, we recommend implementing the suggested global solution for password security.

If the user indicates that there was suspicious activity, we additionally recommend implementing user-specific alerts with a threshold calculated based on their individual data. 

**Search Queries used:**

Filter by user to view top signatures:
`source="windows_server_attack_logs.csv" host="windows_server_attack_logs" user=user_k | timechart count by signature limit=10`

Filtuer by signature to view if other activities occured at the time of the suspect signature activity:
`source="windows_server_attack_logs.csv" host="windows_server_attack_logs" user=user_k signature!="An attempt was made to reset an accounts password" | timechart count by signature limit=10`

`source="windows_server_attack_logs.csv" host="windows_server_attack_logs" user=user_a | timechart count by signature`

---

## 2. `user_a`: `A user account was locked out`

Here is evidence of the brute force attack filtered specifically for `user_a`:

![user_a_signatures](https://raw.githubusercontent.com/yffenim/splunk_attack_visualizations/main/images/user_a_signatures.png)

We can see that the user account was locked out during the time between Tues, March 24th 2022 at approximately 8pm to 11pm. 

![user_a_signatures_for_time](https://github.com/yffenim/splunk_attack_visualizations/blob/main/images/user_a_filtered_by_signature_for_time.png)

In order to check account activity within that timeframe, we can filter by time and remove the account lockout signature we already know. From here, we can see despite the account lockout, many changes to the account occured which is evidence of compromise.

![user_a_signatures_filtered](https://raw.githubusercontent.com/yffenim/splunk_attack_visualizations/main/images/user_a_filtered_by_signature_for_time_II.png)


## User Migitation Recommendations**

The logs for `user_a` show that an attacker was repeatedly attempting to brute force their password, triggering the account lock out mechanism. Examining the account further within the attack timeframe, we can see that many changes were made to the account, indicating comprise. We recommend that this account be immediately locked until a thorough audit can be performed to access impact. The user must also implement MFA and change their password according to the guidelines in Global Solutions. 

**Search Queries:**

Filter by user to show top signature:
`source="windows_server_attack_logs.csv" host="windows_server_attack_logs" user=user_a signature!="A user account was locked out" | timechart count by signature`

Filter by time with locked-out signature removed:
`source="windows_server_attack_logs.csv" host="windows_server_attack_logs" user=user_a signature!="A user account was locked out" | timechart count by signature`

---

## 3. `user_j`: `A user account was successfully logged on`**

This log shows that someone was able to successfully logon to this `user_j`'s account:

![user_j_signatures](https://raw.githubusercontent.com/yffenim/splunk_attack_visualizations/main/images/user_j%20_signatures.png)

Interestingly, when we filter out the logon signature, we do not see any suspicious account activity logged. In addition, none of the activites after the logon timeframe are evidently suspicious as they are similar in volume to baseline. 

![user_j_signatures_filtered](https://raw.githubusercontent.com/yffenim/splunk_attack_visualizations/main/images/user_j_signatures_II.png)

**Migitation Recommendations**

The logs for `user_j` indicate that the attacker was able to successfully obtain user credentials and logon to the account. We recommend immediately locking the account and performing a full audit to determine impact. We futher recommend the user implement MFA and the global solutions recommended for password security. If additional measures are needed, we recommend that (similar to `user_k`) an individualized baseline is take for account activity in order to set user-specific alerts.

**Search Queries:**

Filter by user to show top signature:
`source="windows_server_attack_logs.csv" host="windows_server_attack_logs" user=user_j | timechart count by signature limit=10`

Filter by time with logged-on signature removed:
`source="windows_server_attack_logs.csv" host="windows_server_attack_logs" user=user_j signature!="An account was successfully logged on"| timechart count by signature`

---

# Part 2: Apache Webserver Attack

First, we can use the Splunk command `iplocation clientip` to extract the `Country` of origin for the requests to make the data more human-readable and establish a baseline:

![apache_baseline_countries](https://raw.githubusercontent.com/yffenim/splunk_attack_visualizations/main/images/apache_baseline_countries.png)

When we compare this to the same filter using the attack logs, we can see that Ukraine has the second most incoming requests whereas they are not normally notable.

![apache_attack_countries](https://github.com/yffenim/splunk_attack_visualizations/blob/main/images/apache_attack_countries.png)

Since this is a web attack, we can also filter by request method to establish a baseline for request types. We can see that it's mostly `GET` requests on a normal day:

![apache_baseline_country_method](https://raw.githubusercontent.com/yffenim/splunk_attack_visualizations/main/images/apache_baseline_country_method.png)

Running the same filter on the attack logs shows that we suddenly have an high volume of `POST` requests (which means that someone is attempt to submit data to the server; mostly a `LOGON` attempt in this case) coming from Ukraine and United States. This further suggests that Ukraine is where our attack originates from. Since there are also `POST` requests originating from the US, it's  possible that the American servers have been compromised and are now sending data back to the Ukraine:

![apache_attack_country_method](https://raw.githubusercontent.com/yffenim/splunk_attack_visualizations/main/images/apache_attack_country_method.png)

Using the `geostats` command as requested by the assignment though the comparison isn't very semantically useful as a visualization.

![apache_baseline_geo](https://raw.githubusercontent.com/yffenim/splunk_attack_visualizations/main/images/apache_baseline_geo.png)

![apache_attack_geo](https://raw.githubusercontent.com/yffenim/splunk_attack_visualizations/main/images/apache_attack_geo.png)

A way to improve the results would be to add the `method` filter:

![apache_attack_geo_method](https://raw.githubusercontent.com/yffenim/splunk_attack_visualizations/main/images/apache_attack_geo_method.png)


### Recommended Firewall Rule & Description 

We recommened setting up a rule that will block repeated and consecutive `POST` requests from the same `IP`. We can also implement user lockout if there are repeated `LOGON` attempts above an established baseline. 

In plain words, the firewall rule: "Block all incoming HTTP traffic from the same IP if there are a lot of consecutive requests within a period of time." 

