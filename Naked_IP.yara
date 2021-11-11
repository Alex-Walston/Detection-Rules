rule Naked_IP{
  meta:
    // Looks for outbound connections to `naked` Ips
    author = "Alex Walston"
    description = "Connections to `naked` Ips"
    severity = "Medium"

  events:
(
    re.regex($e.target.url,`(http|https):\/\/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b.*`)
    or
    re.regex($e.src.url,`(http|https):\/\/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b.*`)
    or
    re.regex($e.principal.url,`(http|https):\/\/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b.*`)
    or
    re.regex($e.target.url,`(http|https):\/\/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b.*`)
)   
    and not 
(
    //Internal A Class
    re.regex($e.target.url,`(http|https):\/\/(10)(\.([2]([0-5][0-5]|[01234][6-9])|[1][0-9][0-9]|[1-9][0-9]|[0-9])){3}.*`)
    or
    //Internal B Class
    re.regex($e.target.url,`(http|https):\/\/(172)\.(1[6-9]|2[0-9]|3[0-1])(\.(2[0-4][0-9]|25[0-5]|[1][0-9][0-9]|[1-9][0-9]|[0-9])){2}.*`)
    or
    //Internal C Class
    re.regex($e.target.url,`(http|https):\/\/(192)\.(168)(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])){2}.*`)
)
  condition:
    $e
}
