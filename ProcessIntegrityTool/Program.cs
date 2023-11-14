using System.Diagnostics;

namespace ProcessIntegrityTool
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Process Integrity Tool started!\n");

            var exit = false;

            try
            {
                while (!exit)
                {
                    ProcessIntegrity integrity = new ProcessIntegrity();
                    Process process = null;

                    var isInputvalid = false;

                    while (!isInputvalid)
                    {
                        Console.WriteLine("Please enter 1 to specify a process ID to inspect or press 2 to inspect the current process...");
                        var input = int.Parse(Console.ReadLine());

                        if (input == 1)
                        {
                            isInputvalid = true;
                            Console.WriteLine("Please enter the PID of the process you would like to inspect: ");
                            var pid = int.Parse(Console.ReadLine());
                            process = Process.GetProcessById(pid);
                            continue;
                        }
                        else if (input == 2)
                        {
                            isInputvalid = true;
                            process = Process.GetCurrentProcess();
                        }
                        else
                        {
                            Console.WriteLine("\nThe input you provided was not a valid option, please try again...\n");
                        }
                    }


                    var processSecuityMandatoryLevel = integrity.GetProcessSecuityMandatoryLevel(process);

                    Console.WriteLine($"\nSecuity Mandatory Level of the current process (PID -> {process.Id}): " + processSecuityMandatoryLevel);

                    var isProcessRunningElevated = integrity.IsProcessRunningElevated(process);

                    Console.WriteLine($"The current process (PID -> {process.Id}) is running elevated: " + isProcessRunningElevated);

                    isInputvalid = false;

                    while (!isInputvalid)
                    {
                        Console.WriteLine("\nWould you like to investigate another process? Enter 1 for YES, enter 2 for NO...");
                        var input = int.Parse(Console.ReadLine());

                        if (input == 1)
                        {
                            isInputvalid = true;
                            continue;
                        }
                        else if (input == 2)
                        {
                            isInputvalid = true;
                            exit = true;
                        }
                        else
                        {
                            Console.WriteLine("\nThe input you provided was not a valid option, please try again...");
                        }
                    }
                }
            }
            catch (Exception ex) 
            {
                Console.WriteLine("\nReceived the following exception: " + ex.ToString());
                Console.ReadLine();
            }

            Console.WriteLine("\nExiting out of Process Integrity Tool...");
        }
    }
}
