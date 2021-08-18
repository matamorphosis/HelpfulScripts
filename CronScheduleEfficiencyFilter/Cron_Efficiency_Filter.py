#!/usr/bin/env python3
# Cron Filtering for Unix and Quartz cron schedules.
import os, re, sys, datetime

def Get_Date():

    try:
        return datetime.datetime.now()

    except Exception as e:
        sys.exit(f"[-] Failed to verify and filter provided cron schedule. {str(e)}.")

class Main:

    def __init__(self, Input_File, Output_File, Cron_Type):

        try:

            if os.path.exists(Input_File):
                self.Input_File = Input_File
                self.Output_File = Output_File
                self.Cron_Type = Cron_Type
                File = open(self.Input_File, "r")
                self.File_Contents = File.read().splitlines()
                File.close()

        except Exception as e:
            sys.exit(f"{str(Get_Date())} - Exception Error: Failed to initialise object. {str(e)}.")

    def Commence_Filter(self):

        try:
            self.Output_File_Contents = []

            for Cron_Schedule in self.File_Contents:
                Updated_Cron = []

                if self.Cron_Type == "Unix":
                    Frequency_Regex = re.search(r"^([\d\/\*\-\,]+)\s([\d\/\*\-\,]+)\s([\d\/\*\-\,]+)\s([\d\/\*\-\,]+)\s([\d\/\*\-\,]+)$", Cron_Schedule)
                    
                    for Group in range(1, 6):
                        Items = {1: [0, 59], 2: [0, 23], 3: [1, 31], 4: [1, 12], 5: [0, 6]}
                        Regex_Group = Frequency_Regex.group(Group)
                        
                        if "," in Regex_Group:
                            self.Segment_List = Regex_Group.split(",")
                            Item = self.Cron_Efficiency_Filter(Items[Group][0], Items[Group][1])
                            Updated_Cron.append(",".join(Item))

                        else:
                            Updated_Cron.append(Regex_Group)

                    self.Output_File_Contents.append(" ".join(Updated_Cron))

                elif self.Cron_Type == "Quartz":
                    Frequency_Regex = re.search(r"^([\d\/\*\-\,]+)\s([\d\/\*\-\,]+)\s([\d\/\*\-\,]+)\s([\w\/\*\-\,]+)\s([\w\/\*\-\,]+)\s([\w\/\*\-\,]+)(\s[\w\/\*\-\,]+)?$", Cron_Schedule)

                    for Group in range(1, 8):
                        # 2099 is the highest year supported by Quartz Cron (http://www.quartz-scheduler.org/documentation/quartz-2.3.0/tutorials/crontrigger.html), 1970 is the lowest, but makes no sense to check for years in the past.
                        Items = {1: [0, 59], 2: [0, 59], 3: [0, 23], 4: [1, 31], 5: [1, 12], 6: [1-7], 7: [Get_Date().year, 2099]}

                        if Frequency_Regex.group(Group) is not None:
                            Regex_Group = Frequency_Regex.group(Group).replace(" ", "")
                            
                            if "," in Regex_Group:
                                self.Segment_List = Regex_Group.split(",")
                                Item = self.Cron_Efficiency_Filter(Items[Group][0], Items[Group][1])
                                Updated_Cron.append(",".join(Item))

                            else:
                                Updated_Cron.append(Regex_Group)

                    self.Output_File_Contents.append(" ".join(Updated_Cron))

                else:
                    sys.exit(f"{str(Get_Date())} - Error: Invalid cron type provided.")

            print(f"{str(Get_Date())} - Final cron schedule " + " ".join(Updated_Cron))

        except Exception as e:
            sys.exit(f"{str(Get_Date())} - Exception Error: Failed to commence cron filtering. {str(e)}.")
    
    def Output_Updated_Cron_Schedules(self):

        try:
            New_File = open(self.Output_File, "w")
            print(self.Output_File_Contents)
            New_File.write("\n".join(self.Output_File_Contents))
            New_File.close()

        except Exception as e:
            sys.exit(f"{str(Get_Date())} - Exception Error: Failed to output the updated cron schedules. {str(e)}.")

    def Cron_Efficiency_Filter(self, Start_Number, End_Number):

        try:

            def Dash_to_Numbers(Segment):
                List_of_Numbers = []
                Segments = Segment.split("-")
                Iterator = int(Segments[0])

                while Iterator <= int(Segments[1]):
                    List_of_Numbers.append(str(Iterator))
                    Iterator += 1

                return List_of_Numbers

            Segment_List_Filtered = []

            for Segment_Item in self.Segment_List:

                if "-" in Segment_Item:
                    Segment_Item = Dash_to_Numbers(Segment_Item)
                    Segment_List_Filtered.extend(Segment_Item)

                else:
                    Segment_List_Filtered.append(Segment_Item)

            Non_Hardcoded_Segment_List = []
            Updated_Segment_List = []
            Iterator = 0
            Range_End = End_Number + 1
            Approved_Hours = list(range(Start_Number, Range_End))

            while Iterator < len(Segment_List_Filtered):
                Segment_Item = Segment_List_Filtered[Iterator]

                if Segment_Item != Segment_List_Filtered[-1] and "/" not in Segment_Item:
                    Seg_Iter = 1
                    First_Segment = Segment_Item
                    Current_Segment = Segment_Item

                    if (Iterator + Seg_Iter) < len(Segment_List_Filtered):
                        Current_Next_Value = Segment_List_Filtered[Iterator + Seg_Iter]
                        
                        while all(Seg.isnumeric() for Seg in [Current_Next_Value, Current_Segment]) and int(Current_Next_Value) in Approved_Hours and ((int(Current_Next_Value) - int(Current_Segment)) == 1):
                            Current_Segment = Current_Next_Value
                            Seg_Iter += 1
                            Curr_Iter = Iterator + Seg_Iter

                            if (Iterator + Seg_Iter) < len(Segment_List_Filtered):
                                Current_Next_Value = Segment_List_Filtered[Curr_Iter]

                            else:
                                break

                        if int(First_Segment) == End_Number:
                            Updated_Segment_List.append(First_Segment)

                        else:
                            Updated_Segment_List.append(First_Segment + "-" + Current_Segment)

                        Iterator += Seg_Iter

                elif any(Char in Segment_Item for Char in ["/", "?"]) or any(Seg.isalpha() for Seg in Segment_Item):
                    Non_Hardcoded_Segment_List.append(Segment_Item)
                    Iterator += 1
                
                else:
                    Iterator += 1

            if f"{str(Start_Number)}-{str(End_Number)}" in Updated_Segment_List:
                return ["*"]

            else:
                Updated_Segment_List.extend(Non_Hardcoded_Segment_List)
                return Updated_Segment_List

        except Exception as e:
            sys.exit(f"{str(Get_Date())} - Exception Error: Failed to verify and filter provided cron schedule. {str(e)}.")

if __name__ == "__main__":

    try:
        import argparse
        Parser = argparse.ArgumentParser(description='Makes automated adjustments for cron schedules.')
        Parser.add_argument('-if', '--inputfile', type=str, required=True, help='This option specifies the input location of the cron schedules.')
        Parser.add_argument('-of', '--outputfile', type=str, required=True, help='This option specifies the output location of the cron schedules.')
        Parser.add_argument('-t', '--type', type=str, default="Unix", choices=["Unix", "Quartz"], help='This option specifies the type of cron to use. Options include:\n1. Unix\n2. Quartz')
        Arguments = Parser.parse_args()
        InFile = Arguments.inputfile
        OutFile = Arguments.outputfile
        Type = Arguments.type

        if InFile != OutFile:
            Obj = Main(InFile, OutFile, Type)
            Obj.Commence_Filter()
            Obj.Output_Updated_Cron_Schedules()

        else:
            sys.exit(f"{str(Get_Date())} - Error: The input and output directories cannot be the same.")                

    except Exception as e:
        exit(f"{str(Get_Date())} - Exception Error: {str(e)}.")