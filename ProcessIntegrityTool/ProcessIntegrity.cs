using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ProcessIntegrityTool
{
    /// <summary>
    /// This class provides methods for (1) getting a process Security Mandatory Level and (2) determining if a process is running "elevated".
    /// </summary>
    public class ProcessIntegrity
    {
        /// <summary>
        /// Represents each Security Mandatory Level with their corresponding Relative Identifier (RID) values and descriptions.
        /// Values defined here: https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
        ///
        /// NOTE: The last two values (SECURITY_MANDATORY_SECURE_PROCESS_RID and SECURITY_MANDATORY_APP_CONTAINER_RID) were not introduced to Windows OS
        /// until Windows 10. These values have been added as most people would be running on either Win10 or Win11. If this code is run on an earler version
        /// of Windows, these values will not be applicable.
        /// </summary>
        public enum SecurityMandatoryLevel
        {
            /// <summary>
            /// Untrusted. Sandboxed apps, restricted web browsers. This would be considered an "unelevated" process.
            /// 
            /// Hexadecimal value -> 0x00000000
            /// </summary>
            SECURITY_MANDATORY_UNTRUSTED_RID = 0,

            /// <summary>
            /// Low integrity (e.g. standard user-mode apps). This would be considered an "unelevated" process.
            /// 
            /// Hexadecimal value -> 0x00001000
            /// </summary>
            SECURITY_MANDATORY_LOW_RID = 4096,

            /// <summary>
            /// Medium integrity (e.g. most user-mode apps, user-mode services). This would be considered an "unelevated" process.
            /// 
            /// Hexadecimal value -> 0x00002000
            /// </summary>
            SECURITY_MANDATORY_MEDIUM_RID = 8192,

            /// <summary>
            /// Medium high integrity (e.g. medium + UI access). This would be considered an "unelevated" process.
            /// 
            /// Hexadecimal value -> SECURITY_MANDATORY_MEDIUM_RID + 0x100
            /// </summary>
            SECURITY_MANDATORY_MEDIUM_PLUS_RID = 8448,

            /// <summary>
            /// High integrity (e.g. admin tools, elevated command prompt). This would be considered an "elevated" process.
            /// 
            /// Hexadecimal value -> 0X00003000
            /// </summary>
            SECURITY_MANDATORY_HIGH_RID = 12288,

            /// <summary>
            /// System integrity. (e.g. Windows core system services, kernel mode drivers). This would be considered an "elevated" process.
            /// 
            /// Hexadecimal value -> 0x00004000
            /// </summary>
            SECURITY_MANDATORY_SYSTEM_RID = 16384,

            /// <summary>
            /// Protected process. (e.g. Windows Defender Antivirus). This would be considered an "elevated" process.
            /// 
            /// Hexadecimal value -> 0x00005000
            /// </summary>
            SECURITY_MANDATORY_PROTECTED_PROCESS_RID = 20480,

            /// <summary>
            /// Secure process (e.g. Trusted components with elevated pivileges). This would be considered an "elevated" process.
            /// 
            /// Hexadecimal value -> 0x00007000
            /// 
            /// NOTE: this value is not available on pre-Win10 OS
            /// </summary>
            SECURITY_MANDATORY_SECURE_PROCESS_RID = 28672,

            /// <summary>
            /// App container (e.g. applications in AppContainers, Microsoft Store Apps). This would be considered an "unelevated" process.
            /// 
            /// Hexadecimal value -> 0x00008000
            /// 
            /// NOTE: this value is not available on pre-Win10 OS
            /// </summary>
            SECURITY_MANDATORY_APP_CONTAINER_RID = 32768
        }

        /// <summary>
        /// As defined here: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class
        /// </summary>
        enum TokenInformationClass
        {
            TokenIntegrityLevel = 25
        }

        const uint TOKEN_QUERY = 0x0008;

        /// <summary>
        /// Constructor.
        /// </summary>
        public ProcessIntegrity()
        {
        }

        /// <summary>
        /// Determines if a process is running "elevated".
        /// 
        /// Process "elevation" is NOT the same as a process running as administrator. It is possible for a process to be running with "elevated" privileges WITHOUT
        /// running as admin. This method handles that scenario.
        /// 
        /// A process is considered "elevated" if it is running under one of the following Security Mandatory Levels:
        ///     - SECURITY_MANDATORY_HIGH_RID
        ///     - SECURITY_MANDATORY_SYSTEM_RID
        ///     - SECURITY_MANDATORY_PROTECTED_PROCESS_RID
        ///     - SECURITY_MANDATORY_SECURE_PROCESS_RID
        ///     
        /// All other Security Mandatory Levels are considered "unelevated".
        /// </summary>
        /// <param name="process"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public bool IsProcessRunningElevated(Process process)
        {
            if (process == null)
            {
                throw new ArgumentNullException(nameof(process));
            }

            var integrityLevel = GetProcessSecuityMandatoryLevel(process);

            switch (integrityLevel)
            {
                case SecurityMandatoryLevel.SECURITY_MANDATORY_HIGH_RID:
                    return true;
                case SecurityMandatoryLevel.SECURITY_MANDATORY_SYSTEM_RID:
                    return true;
                case SecurityMandatoryLevel.SECURITY_MANDATORY_PROTECTED_PROCESS_RID:
                    return true;
                case SecurityMandatoryLevel.SECURITY_MANDATORY_SECURE_PROCESS_RID:
                    return true;
                default:
                    return false;
            }
        }

        /// <summary>
        /// This method determines the Security Mandatory Level that a process is running under.
        /// </summary>
        /// <param name="process"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="InvalidOperationException"></exception>
        /// <exception cref="Win32Exception"></exception>
        public SecurityMandatoryLevel GetProcessSecuityMandatoryLevel(Process process)
        {
            if (process == null) 
            { 
                throw new ArgumentNullException(nameof(process));
            }

            IntPtr pId = IntPtr.Zero;
            IntPtr tokenHandle = IntPtr.Zero;
            IntPtr tokenInformation = IntPtr.Zero;

            try
            {
                // first, get the process ID of the process we are investigating
                pId = (process.Handle);

                // get the process handle and inspect it for the Secuity Mandatory Level. If we cannt get the process handle successfully, we will throw an exception.
                if(OpenProcessToken(pId, TOKEN_QUERY, out tokenHandle))
                {
                    uint tokenInformationLength = 0;

                    // get the length of the token information containing the Secuity Mandatory Level
                    GetTokenInformation(tokenHandle, TokenInformationClass.TokenIntegrityLevel, IntPtr.Zero, 0, out tokenInformationLength);

                    // if the token information length is still zero, we know that we were not able to properly access the Secuity Mandatory Level information we need.
                    // We will throw an exception.
                    if (tokenInformationLength == 0)
                    {
                        throw new InvalidOperationException("Failed to get token info length.");
                    }

                    // now we will allocate the correct memory buffer length for the token Secuity Mandatory Level information
                    tokenInformation = Marshal.AllocCoTaskMem((int)tokenInformationLength);

                    // since we know the buffer length for the token Secuity Mandatory Level information, we will call GetTokenInformation to get the actual Secuity Mandatory Level information
                    if (GetTokenInformation(tokenHandle, TokenInformationClass.TokenIntegrityLevel, tokenInformation, tokenInformationLength, out tokenInformationLength))
                    {
                        // access the pointer to the token SID info containing the Secuity Mandatory Level of the process
                        IntPtr pSid = Marshal.ReadIntPtr(tokenInformation);

                        // find the last index of th SID sub authority list and get its integer value
                        int integrityLevelInteger = Marshal.ReadInt32(GetSidSubAuthority(pSid, (Marshal.ReadByte(GetSidSubAuthorityCount(pSid)) - 1U)));

                        // if the integrity level integer value matches with one of the integer values defined in the SecurityMandatoryLevel enum, we will return
                        // the corresponding enum value. Otherwise, throw exception.
                        if (Enum.IsDefined(typeof(SecurityMandatoryLevel), (SecurityMandatoryLevel)integrityLevelInteger))
                        {
                            return (SecurityMandatoryLevel)integrityLevelInteger;
                        }
                        else
                        {
                            throw new InvalidOperationException("Failed to get the Secuity Mandatory Level of the process");
                        }
                    }
                    else
                    {
                        int error = Marshal.GetLastWin32Error();
                        throw new Win32Exception(error);
                    }
                }
                else
                {
                    int error = Marshal.GetLastWin32Error();
                    throw new Win32Exception(error);
                }
            }
            finally
            {
                // release token information if we have not already
                if (tokenInformation != IntPtr.Zero)
                {
                    Marshal.FreeCoTaskMem(tokenInformation);
                }

                // release toke handle if we have not already
                if(tokenHandle != IntPtr.Zero)
                {
                    CloseHandle(tokenHandle);
                }
            }
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern IntPtr GetSidSubAuthority(IntPtr sid, uint subAuthorityIndex);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool GetTokenInformation(IntPtr tokenHandle, TokenInformationClass tokenInformationClass, IntPtr tokenInformation, uint tokenInformationLength, out uint returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);
    }
}
