# idshwk3
Detection Requirement
• check http sessions and if a source IP is related to three different user-agents or more
• output “xxx.xxx.xxx.xxx is a proxy” where xxx.xxx.xxx.xxx is the source IP
Need
• a global variable to store the relationship of sourceIP to user-agent
• write a event which can return you the http header user_agent information
• you may need to study the datatype of Table, Set, String,
• to_lower(str) return a lowercase version string of the original one
• you may use print to output the alert
