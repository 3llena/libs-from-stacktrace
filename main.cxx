#include "sdk/sdk.hxx"

std::int32_t main( )
{
   kernel32::m_image = utils::stack_image( "KERNEL32" );
   advapi32::m_image = kernel32::load_library( "advapi32" );
   ntdll::m_image = kernel32::load_library( "ntdll" );

   std::cout << std::hex << "kernel32.dll 0x" << std::hex << ptr< std::uintptr_t >( kernel32::m_image ) << "\n";
   std::cout << std::hex << "advapi32.dll 0x" << std::hex << ptr< std::uintptr_t >( advapi32::m_image ) << "\n";
   std::cout << std::hex << "ntdll.dll 0x" << std::hex << ptr< std::uintptr_t >( ntdll::m_image ) << "\n";

   std::cin.get( );
}
