# Cron Schedule Efficiency Filter
This versatile script, has a very simple purpose, to convert stupidly-written cron schedules to be more simple and efficient.

For example, let's say someone new to cron, wants to run the schedule every 5 minutes, on hours 1-5; however, they supply the hours individually like so:  
`*/5 1,2,3,4,5 * * *`  
The script goes through each segment of the schedule, and ensures simplicity, in this case, it would convert the hour segment into a list of numbers, iterate through them, and convert it to use the first number and last number of that list, with a dash in between:  
`*/5 1-5 * * *`  
If the schedule, has multiple sections of iterating hours, with gaps in-between, like so:  
`*/5 1,2,5,6 * * *`  
It will become:  
`*/5 1-2,5-6 * * *`  
If the segment contains all possible values for that segment (0-23) for the hour segment, like so:  
`*/5 0-12,13-23 * * *`  
The script will simply return an asterisk in it's place, as there is no point in specifying the full range of hours in a single schedule:  
`*/5 * * * *`

This script supports both Unix and Quartz schedules, the above example uses Unix syntax.  
The usage of the script is as follows:  
```console
user@system:$ python3 CronScheduleEfficiencyFilter.py -if <Name of file with schedules inside, separated by newlines> -of <Output file name> -t <type of schedule (Unix or Quartz)>
```