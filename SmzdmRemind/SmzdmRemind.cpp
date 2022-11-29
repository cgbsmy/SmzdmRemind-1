// SmzdmRemind.cpp : 定义应用程序的入口点。
//
#if defined _M_IX86
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_IA64
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='ia64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_X64
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#else
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif

#include "framework.h"
#include "SmzdmRemind.h"
#include "shellapi.h"
#include "commctrl.h"
#include "psapi.h"

typedef BOOL (WINAPI* pfnShowToast)(WCHAR* szTitle, WCHAR* szBody, WCHAR* szImagePath, WCHAR* szLink);
pfnShowToast ShowToast;

wchar_t* lstrstr(const wchar_t* str, const wchar_t* sub)
{
	int i = 0;
	int j = 0;
	while (str[i] && sub[j])
	{
		if (str[i] == sub[j])//如果相等
		{
			++i;
			++j;
		}
		else		     //如果不等
		{
			i = i - j + 1;
			j = 0;
		}
	}
	if (!sub[j])
	{
		return (wchar_t*)&str[i - lstrlen(sub)];
	}
	else
	{
		return (wchar_t*)0;
	}
}

#define CookieSize 16*1024
WCHAR wCookieFileName[9][12] = { L"cookie1.txt" ,L"cookie2.txt",L"cookie3.txt",L"cookie4.txt",L"cookie5.txt" ,L"cookie6.txt" ,L"cookie7.txt",L"cookie8.txt",L"cookie9.txt" };

void ReadCookieFromFile(int n, LPWSTR lpCookie)
{
	ZeroMemory(lpCookie, CookieSize * sizeof WCHAR);
	HANDLE hFile = CreateFile(wCookieFileName[n], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_ARCHIVE, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		WORD unicode_identifier = 0xfeff;
		DWORD dSize;
		ReadFile(hFile, &unicode_identifier, sizeof(WORD), &dSize, NULL);
		ReadFile(hFile, lpCookie, CookieSize * sizeof(WCHAR) - 1, &dSize, NULL);
		CloseHandle(hFile);
	}
}
void WriteCookieToFile(int n,LPWSTR lpCookie)
{
    HANDLE hFile = CreateFile(wCookieFileName[n], GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_ARCHIVE, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
		WORD unicode_identifier = 0xfeff;
		DWORD dSize;
        WriteFile(hFile, &unicode_identifier, sizeof(WORD), &dSize, NULL);
        WriteFile(hFile, lpCookie, lstrlen(lpCookie) * 2, &dSize, NULL);
        CloseHandle(hFile);
    }
}


WCHAR szUserAgent[] = L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36 Edg/106.0.1370.52";
RTL_OSVERSIONINFOW rovi;//WIN系统版本号
int winhttpDownload(WCHAR* wUrl, WCHAR* wFile)
{
    HANDLE hFile = CreateFile(wFile,  // creates a new file
        FILE_APPEND_DATA,         // open for writing
        0,          // allow multiple readers
        NULL,                     // no security
        CREATE_ALWAYS,            // creates a new file, always.
        FILE_ATTRIBUTE_NORMAL,    // normal file
        NULL);                    // no attr. template        
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return 2;
    }
	DWORD dwSize = 0;
	DWORD dwSumSize = 0;
	DWORD dwDownloaded = 0;
	DWORD dwBuffer = 0,
		dwBufferLength = sizeof(DWORD),
		dwIndex = 0;
	LPSTR pszOutBuffer;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL,
        hConnect = NULL,
        hRequest = NULL;

	hSession = WinHttpOpen(szUserAgent, WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, NULL);
	if (rovi.dwMajorVersion == 6 && rovi.dwMinorVersion == 1)//WIN 7 开启TLS1.2
	{
		DWORD flags = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
		WinHttpSetOption(hSession, WINHTTP_OPTION_SECURE_PROTOCOLS, &flags, sizeof(flags));
	}

    // Specify an HTTP server.
    //INTERNET_PORT nPort = (pGetRequest->fUseSSL) ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
	WCHAR* wHost = lstrstr(wUrl, L":");
    if (wHost)
        wHost += 2;
    else
        wHost = wUrl;
    WCHAR* wUrlPath = lstrstr(wHost, L"/");    
    WCHAR szHost[128];
    lstrcpyn(szHost, wHost,int(wUrlPath - wHost+1));
    if (hSession)
        hConnect = WinHttpConnect(hSession, szHost,
            //hConnect = WinHttpConnect(hSession, L"avatar.csdn.net",
            INTERNET_DEFAULT_HTTPS_PORT, 0);
    // Create an HTTP request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", wUrlPath,
            L"HTTP/1.1", WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);
	// Create an HTTP request handle.
	if (rovi.dwMajorVersion == 6 && rovi.dwMinorVersion == 1)//WIN 7 开启TLS1.2
	{
		DWORD dwSecFlag = SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
			SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
			SECURITY_FLAG_IGNORE_UNKNOWN_CA |
			SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
		WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwSecFlag, sizeof(dwSecFlag));
	}
    // Send a request.
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0, WINHTTP_NO_REQUEST_DATA, 0,
            0, 0);

    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER, NULL, &dwBuffer, &dwBufferLength, &dwIndex);
    // Continue to verify data until there is nothing left.
    if (bResults)
    {
        do
        {
            // Verify available data.
            dwSize = 0;
            WinHttpQueryDataAvailable(hRequest, &dwSize);
            // Allocate space for the buffer.
            pszOutBuffer = new char[dwSize + (size_t)1];
            if (!pszOutBuffer)
            {
                dwSize = 0;
            }
            else
            {
                dwSumSize += dwSize;
                // Read the Data.
                ZeroMemory(pszOutBuffer, dwSize + (size_t)1);

                if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
                    dwSize, &dwDownloaded)) {
                }
                else {
                    WriteFile(hFile, pszOutBuffer, dwDownloaded, &dwDownloaded, NULL);
                }
                // Free the memory allocated to the buffer.
                delete[] pszOutBuffer;
            }

        } while (dwSize > 0);        
    }
	// Close open handles.	
    if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);
	// Close files.
	CloseHandle(hFile);
    return 0;
}
#define NETPAGESIZE 2097152
#define MAX_LOADSTRING 100
#define WM_IAWENTRAY WM_USER+199
// 全局变量:
WCHAR szAppName[] = L"SmzdmRemind";
HINSTANCE hInst;                                // 当前实例
HANDLE hMutex = NULL;
HMODULE hWintoast;
HWND hMain;
HWND hSetting;
HWND hList;
HWND hListRemind;
HWND hCombo;
HWND hComboTime;
HWND hComboPage;
HWND hComboSound;
HWND hComboSendMode;
HWND hComboSearch;
HWND hComBoPercentage;
HANDLE hMap = NULL;
HANDLE hGetDataThread;
HANDLE hGetZhiThread=NULL;
NOTIFYICONDATA nid;
HICON iMain;
//HICON iTray;
//BOOL bPost = FALSE;//社区文章
BOOL bOpen = FALSE;//程序第一次获取数据
BOOL bExit = FALSE;//退出线程
BOOL bResetTime = FALSE;//重新设置时间
BOOL bGetData = FALSE;//是否获取数据中
BOOL bNewTrayTips = FALSE;//新的通知样式
WCHAR szWxPusherToken[] = L"AT_YGOXF3ZtPSkz5lkxhFUZ5ZkHOgrkKSdG";
WCHAR szRemindSave[] = L"SmzdmRemind.sav";
WCHAR szRemindHtml[] = L"SmzdmRemind.html";
WCHAR szRemindItem[] = L"SmzdmRemind.item";
WCHAR szRemindList[] = L"SmzdmRemind.list";
DWORD iTimes[] = { 1,3,5,10,15,30 };
WCHAR szTimes[][5] = {L"1分钟",L"3分钟",L"5分钟",L"10分钟",L"15分钟",L"30分钟"};
int mIDs[24] =          { 0,  183 ,   20057,  3949,       2537,       247,        241,      6753,               2897,       243,       8645,      257,       8912,        239,        4031,       20155,      269,           4033,           5108,       3981,        20383,      167 ,      153,    6255 };
WCHAR szBus[24][9] =    { L"" , L"京东",L"京喜",L"京东国际",L"天猫超市",L"天猫精选",L"聚划算",L"天猫国际官方直营",L"天猫国际",L"淘宝精选",L"拼多多",L"唯品会", L"小米有品", L"苏宁易购",L"苏宁国际", L"抖音电商",L"亚马逊中国",L"亚马逊海外购",L"网易严选", L"考拉海购",L"微信小程序",L"真快乐",L"当当",L"什么值得买" };
WCHAR szPage[9][2] = {L"1",L"2",L"3",L"4",L"5",L"6",L"7",L"8",L"9"};
WCHAR szBarkSound[32][19] = {L"alarm", L"anticipate", L"bell", L"birdsong", L"bloom", L"calypso", L"chime", L"choo", L"descent", L"electronic", L"fanfare", L"glass", L"gotosleep", L"healthnotification", L"horn", L"ladder", L"mailsent", L"minuet", L"multiwayinvitation", L"newmail", L"newsflash", L"noir", L"paymentsuccess", L"shake", L"sherwoodforest", L"silence", L"spell", L"suspense", L"telegraph", L"tiptoes", L"typewriters", L"update"};
WCHAR szSendMode[][9] = { L"按全局设置",L"打开网页",L"任务栏通知",L"企业微信",L"钉钉",L"Bark",L"WxPusher" };
WCHAR szSearch[][5] = {L"列表视图",L"图文列表",L"进入网站"};
int iPercentages[] = { 0,50,60,70,80,90 };
WCHAR szPercentage[][3] = { L"",L"50",L"60",L"70",L"80",L"90" };
// 此代码模块中包含的函数的前向声明:
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    MainProc(HWND, UINT, WPARAM, LPARAM);
typedef struct _REMINDITEM
{
    BOOL bNotUse;//暂不获取
    WCHAR szKey[128];//关键词
    WCHAR szFilter[128];//过滤词
    UINT uMinPrice;//最小价格
    UINT uMaxPrice;//最大价格
    int iBusiness;//平台
    UINT uuuid;//商品ID    
    FILETIME ft;//备用时间
    WCHAR szID[10];//文章ID    
    WCHAR szMember[14];
    UINT uTalk;//评论
    UINT oldID[38];
    UINT n;
    BOOL bScore;//综合排序
    UINT uZhi;//值
    UINT uBuZhi;//不值
    UINT uPercentage;//值比率
    int iSend;//推送方式
    BOOL bMemberPost;//值友文章
    WCHAR szMemberID[12];//值友ID;
}REMINDITEM;
REMINDITEM* lpRemindItem = NULL;
typedef struct _SMZDMITEM
{
    WCHAR szTitle[129];//标题
    WCHAR szDescribe[513];//描述
	WCHAR szLink[65];//商品链接
	WCHAR szImg[129];//商品图片
    WCHAR szBusiness[17];//平台
	UINT lZhi;//值
	UINT lBuZhi;//不值
	UINT lStar;//收藏
	UINT lTalk;//评论
    float fPrice;//价格
    SYSTEMTIME st;//时间
    WCHAR szGoPath[511];//直达链接
    BOOL bGrey;
}SMZDMITEM;
typedef struct _REMINDDATA
{
	BOOL bExit;
    WCHAR szWeChatToken[512];
}REMINDDATA;
REMINDDATA* lpRemindData;
DWORD riSize = 0;
typedef struct _REMINDSAVE
{
    BOOL bDirectly;
    BOOL bTips;
    BOOL bWxPusher;    
    BOOL bWeChat;
    int iTime;
    WCHAR szWxPusherUID[64];    
    WCHAR szWeChatAgentId[8];
    WCHAR szWeChatID[24];    
    WCHAR szWeChatSecret[48];
    WCHAR szWeChatUserID[64];
    int iPage;
    BOOL bDingDing;
    WCHAR szDingDingToken[80];
    BOOL bScoreSort;//最新排序
    BOOL bPost;//社区文章
    BOOL bBark;//Bark推送
    WCHAR szBarkUrl[139];
    WCHAR szBarkSound[29];
}REMINDSAVE;
REMINDSAVE RemindSave = {
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    1,
    L"",
    L"",
    L"",
    L"",
    L"@all",
    1,
    FALSE,
    {0},
    FALSE,
    FALSE,
    FALSE,
    {0},
    L"bell"
};
void WriteLog(const WCHAR* wText,BOOL bShow)
{
    WCHAR wLog[1024];
    SYSTEMTIME st;
    GetLocalTime(&st);
    wsprintf(wLog, L"%.2d-%.2d %.2d:%.2d:%.2d %s", st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, wText);
	HWND hList = GetDlgItem(hMain, IDC_LIST_LOG);
	SendMessage(hList, LB_INSERTSTRING, 0, (LPARAM)wLog);
    if (bShow)
    {
        ShowWindow(hList, SW_SHOW);
        ShowWindow(GetDlgItem(hMain, IDC_LIST_REMIND), SW_HIDE);
    }
}
BOOL LoadToast()
{
	HMODULE hWintoast = LoadLibrary(L"WinToast.dll");
	if (hWintoast)
	{
		typedef BOOL(WINAPI* pfnInit)(const WCHAR* szAppName);
		pfnInit Init = (pfnInit)GetProcAddress(hWintoast, "Init");
		if (Init)
		{
			if (Init(L"什么值得买"))
			{
				ShowToast = (pfnShowToast)GetProcAddress(hWintoast, "ShowToast");
				bNewTrayTips = TRUE;
			}
		}
	}
	if (bNewTrayTips == FALSE && hWintoast)
		FreeLibrary(hWintoast);
	return bNewTrayTips;
}
void SetToCurrentPath()////////////////////////////////////设置当前程序为当前目录
{
	WCHAR szDir[MAX_PATH];
	GetModuleFileName(NULL, szDir, MAX_PATH);
	int len = lstrlen(szDir);
	for (int i = len - 1; i > 0; i--)
	{
		if (szDir[i] == L'\\')
		{
			szDir[i] = 0;
			SetCurrentDirectory(szDir);
			break;
		}
	}
}
BOOL bSort = TRUE;
int CALLBACK CompareFunc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
{
    if (lParamSort == 2 || lParamSort == 4|| lParamSort == 5|| lParamSort == 6 || lParamSort == 7)
    {
		WCHAR sz1[129], sz2[129];
		ListView_GetItemText(hList, (int)lParam1,(int)lParamSort, sz1, 128);
		ListView_GetItemText(hList, (int)lParam2, (int)lParamSort, sz2, 128);
        double l1 = my_wtof(sz1);
        double l2 = my_wtof(sz2);
        if (l1 == l2)
            return 0;
        else if (l1 > l2)
        {
            if (bSort)
                return 1;
            else
                return -1;
        }
        else
        {
            if (bSort)
                return -1;
            else
                return 1;
        }
    }
    else
    {
        WCHAR sz1[129],sz2[129];
        ListView_GetItemText(hList, int(lParam1), int(lParamSort), sz1, 128);
        ListView_GetItemText(hList, int(lParam2), int(lParamSort), sz2, 128);
        int s = lstrcmp(sz1, sz2);
        if (bSort&&s!=0)
            s = -s;
        return s;
    }
}
BOOL AutoRun(BOOL GetSet, BOOL bAutoRun, const WCHAR* szName)//读取、设置开机启动、关闭开机启动
{
    BOOL ret = FALSE;
    WCHAR sFileName[MAX_PATH];
    sFileName[0] = L'\"';
    GetModuleFileName(NULL, &sFileName[1], MAX_PATH);
    int sLen = lstrlen(sFileName);
    sFileName[sLen] = L'\"';
    sFileName[sLen + 1] = L' ';
    sFileName[sLen + 2] = L't';
    sFileName[sLen + 3] = L'\0';
    HKEY pKey;
    RegOpenKeyEx(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", NULL, KEY_ALL_ACCESS, &pKey);
    if (pKey)
    {
        if (GetSet)
        {
            if (bAutoRun)
            {
                RegSetValueEx(pKey, szName, NULL, REG_SZ, (BYTE*)sFileName, (DWORD)lstrlen(sFileName) * 2);
            }
            else
            {
                RegDeleteValue(pKey, szName);
            }
            ret = TRUE;
        }
        else
        {
            WCHAR nFileName[MAX_PATH];
            DWORD cbData = MAX_PATH * sizeof WCHAR;
            DWORD dType = REG_SZ;
            if (RegQueryValueEx(pKey, szName, NULL, &dType, (LPBYTE)nFileName, &cbData) == ERROR_SUCCESS)
            {
                if (lstrcmp(sFileName, nFileName) == 0)
                    ret = TRUE;
                else
                    ret = FALSE;
            }
        }
        RegCloseKey(pKey);
    }
    return ret;
}
void UrlUTF8(WCHAR* wstr,WCHAR * wout)
{
    char szUtf8[1024] = { 0 };
    char szout[1024]={0};
	WideCharToMultiByte(CP_UTF8, 0, wstr, -1, szUtf8, 1024, NULL, NULL);
	size_t len = strlen(szUtf8);
	for (size_t i = 0; i < len; i++)
	{
		if (_isalnum((BYTE)szUtf8[i])) //判断字符中是否有数组或者英文
		{
			char tempbuff[2] = { 0 };
			wsprintfA(tempbuff, "%c", (BYTE)szUtf8[i]);
#ifdef NDEBUG
            strcat(szout,tempbuff);
#else
            strcat_s(szout, tempbuff);
#endif
		}
		else if ((BYTE)szUtf8[i]==' ')
		{
#ifdef NDEBUG
            strcat(szout, "+");
#else
            strcat_s(szout, "+");
#endif
            
		}
		else
		{
			char tempbuff[4];
			wsprintfA(tempbuff, "%%%X%X", ((BYTE)szUtf8[i]) >> 4, ((BYTE)szUtf8[i]) % 16);
#ifdef NDEBUG
			strcat(szout, tempbuff);
#else
			strcat_s(szout, tempbuff);
#endif
		}
	}
    ::MultiByteToWideChar(CP_UTF8, NULL, szout, 1024, wout, 1024);
}
BOOL SetForeground(HWND hWnd)//激活窗口为前台
{
    bool bResult = false;
    bool bHung = IsHungAppWindow(hWnd) != 0;
    DWORD dwCurrentThreadId = 0, dwTargetThreadId = 0;
    DWORD dwTimeout = 0;

    dwCurrentThreadId = GetCurrentThreadId();
    dwTargetThreadId = GetWindowThreadProcessId(hWnd, NULL);

    if (IsIconic(hWnd)) {
        //		ShowWindow(hWnd,SW_RESTORE);
        SendMessage(hWnd, WM_SYSCOMMAND, SC_RESTORE, 0);
    }

    if (!bHung) {
        for (int i = 0; i < 10 && hWnd != GetForegroundWindow(); i++) {
            dwCurrentThreadId = GetCurrentThreadId();
            dwTargetThreadId = GetWindowThreadProcessId(GetForegroundWindow(), NULL);
            AttachThreadInput(dwCurrentThreadId, dwTargetThreadId, true);
            SetWindowPos(hWnd, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
            BringWindowToTop(hWnd);
            AllowSetForegroundWindow(ASFW_ANY);
            bResult = SetForegroundWindow(hWnd) != 0;
            AttachThreadInput(dwCurrentThreadId, dwTargetThreadId, false);
            Sleep(10);
        }
    }
    else {
        BringWindowToTop(hWnd);
        bResult = SetForegroundWindow(hWnd) != 0;
    }
    return bResult;
    /*
        int tIdCur = GetWindowThreadProcessId(GetForegroundWindow(), NULL);//获取当前窗口句柄的线程ID
        int tIdCurProgram = GetWindowThreadProcessId(hWnd,NULL);//获取当前运行程序线程ID
        BOOL ret=AttachThreadInput(tIdCur, tIdCurProgram, 1);//是否能成功和当前自身进程所附加的输入上下文有关;
        SetForegroundWindow(hWnd);
        AttachThreadInput(tIdCur, tIdCurProgram, 0);
        return ret;
    */
}
BOOL RunProcess(LPTSTR szExe, const WCHAR* szCommandLine, HANDLE* pProcess)/////////////////////////////////运行程序
{
	BOOL ret = FALSE;
	STARTUPINFO StartInfo;
	PROCESS_INFORMATION procStruct;
	memset(&StartInfo, 0, sizeof(STARTUPINFO));
	StartInfo.cb = sizeof(STARTUPINFO);
	WCHAR* sz;
	WCHAR szName[MAX_PATH];
	if (szExe == (LPTSTR)1)
		sz = NULL;
	else if (szExe)
		sz = szExe;
	else
	{
		GetModuleFileName(NULL, szName, MAX_PATH);
		sz = szName;
	}
	WCHAR szLine[MAX_PATH];
	szLine[0] = L'\0';
	if (szCommandLine)
		lstrcpy(szLine, szCommandLine);
	ret = CreateProcess(sz,// RUN_TEST.bat位于工程所在目录下
		szLine,
		NULL,
		NULL,
		FALSE,
		NULL,// 这里不为该进程创建一个控制台窗口
		NULL,
		NULL,
		&StartInfo, &procStruct);
	if (pProcess == NULL)
		CloseHandle(procStruct.hProcess);
	else
		*pProcess = procStruct.hProcess;
	CloseHandle(procStruct.hThread);
	//	SetTimer(hMain, 11, 1000, NULL);
	return ret;
}
void EmptyProcessMemory(DWORD pID)
{
	HANDLE hProcess;
	if (pID == NULL)
		hProcess = GetCurrentProcess();
	else
	{
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pID);
	}
	SetProcessWorkingSetSize(hProcess, -1, -1);
	EmptyWorkingSet(hProcess);
}
void ItemToHtml(BOOL bList)
{
	WCHAR wHtmlStart[] = L"<!doctype html><html><head><style>button{width:200px;height:30px;color:#ffffff;border:0px;}::-webkit-scrollbar{width:0px;}table{width:1128px;table-layout:fixed;}div{height:120px;text-overflow:ellipsis;overflow:auto;}</style><meta charset=\"utf-8\"><title>SmzdmRemind历史记录</title></head><body style=\"background-color:#eeeeee\"><table style=\"background-color:#eeeeee\" width=\"216\" align=\"center\" cellspacing=\"8\" cellpadding=\"8\"><tbody><tr style=\"background-color:#ffffff\" align=\"center\" valign=\"top\">";
    WCHAR wHtmlLineFeed[] = L"</tr><tr style=\"background-color:#ffffff\" align=\"center\" valign=\"top\">";
    WCHAR wHtmlEnd[] = L"</tr></tbody></table></body></html>";
    HANDLE hFile = CreateFile(szRemindHtml, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_ARCHIVE, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
		DWORD dwBytes = NULL;
		const int UNICODE_TXT_FLG = 0xFEFF;  //UNICODE文本标示
        WriteFile(hFile, &UNICODE_TXT_FLG, 2, &dwBytes, 0);
		WriteFile(hFile, wHtmlStart, lstrlen(wHtmlStart)*2, &dwBytes, NULL);
        int n = 0;        
        HANDLE hItem;
        if(bList)
            hItem= CreateFile(szRemindList, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_ARCHIVE, NULL);
        else
            hItem= CreateFile(szRemindItem, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ| FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_ARCHIVE, NULL);
        if (hItem != INVALID_HANDLE_VALUE)
        {
            int nSI=0;
            int oSI = 0;
            if (!bList)
            {
                nSI=GetFileSize(hItem, 0)/sizeof SMZDMITEM;
                oSI = nSI - 1;
            }
            SMZDMITEM si;
			while (TRUE)
            {
                if(!bList)
                {
					if (nSI == 0)
						break;
                    nSI--;
                    SetFilePointer(hItem, nSI * sizeof SMZDMITEM, 0, FILE_BEGIN);
                }
                ReadFile(hItem, &si, sizeof SMZDMITEM, &dwBytes, NULL);
                if (oSI == nSI && !bList && si.szTitle[127] != L'~')
                {
                    si.szTitle[127] = L'~';
                    SetFilePointer(hItem, nSI * sizeof SMZDMITEM, 0, FILE_BEGIN);
                    DWORD dwBytes = 0;
                    WriteFile(hItem, &si, sizeof SMZDMITEM, &dwBytes, NULL);
                    si.szTitle[127] = L'\0';
                }
                if (dwBytes)
                {
                    int p = int(si.fPrice * 100);
                    WCHAR sz[8192] = L"<td><a target=\"_blank\" href=\"";
                    lstrcat(sz, si.szLink);
                    lstrcat(sz, L"\"><img src=\"https://");
                    lstrcat(sz, si.szImg);
                    lstrcat(sz, L"\" width=\"200\" height=\"200\"></a><a target=\"_blank\" href=\"");
                    lstrcat(sz, si.szGoPath);
                    if (si.szTitle[127] == L'~')
                        lstrcat(sz, L"\"><button style=\"background-color:#3282F6\">上次看到这里</button><br/></a><small><b><p style=\"float:left;text-align:left;color:red\">");
                    else
                        lstrcat(sz, L"\"><button style=\"background-color:#F05656\">直达链接</button><br/></a><small><b><p style=\"float:left;text-align:left;color:red\">");
                    WCHAR sz1[2048];
                    wsprintf(sz1, L"%d.%2.2d元</b><br/><br/>值%d <span style=\"color:#000000\">值%d</span> 评%d</p><p style=\"text-align:right\">%2.2d-%2.2d %2.2d:%2.2d<br/><br/>%s</p><b>",
                        p / 100, p % 100, si.lZhi,si.lBuZhi,si.lTalk, si.st.wMonth, si.st.wDay, si.st.wHour, si.st.wMinute,si.szBusiness);
                    lstrcat(sz, sz1);
                    if(si.bGrey)
                        wsprintf(sz1, L"<p style=\"color:#888888\">%s</p></b></small><font size=\"1\"><div style=\"text-align:left;color:#383838\">", si.szTitle);
                    else
                        wsprintf(sz1, L"<p>%s</p></b></small><font size=\"1\"><div style=\"text-align:left;color:#383838\">", si.szTitle);
                    lstrcat(sz, sz1);
                    lstrcat(sz, si.szDescribe);
                    lstrcat(sz, L"</div></font></td>");
                    WriteFile(hFile, sz, lstrlen(sz) * 2, &dwBytes, NULL);
                    n++;
                    if (n == 5)
                    {
                        n = 0;
                        WriteFile(hFile, wHtmlLineFeed, lstrlen(wHtmlLineFeed) * 2, &dwBytes, NULL);
                    }                    
                }
                else
                    break;
            }
            CloseHandle(hItem);
            WriteFile(hFile, wHtmlEnd, lstrlen(wHtmlEnd) * 2, &dwBytes, NULL);
        }
        else
        {
            CloseHandle(hFile);
            return;
        }
        CloseHandle(hFile);
    }
    ShellExecute(NULL, L"open", szRemindHtml, NULL, NULL, SW_SHOW);
}
void WriteItem(BOOL bList,SMZDMITEM *si)
{
    HANDLE hFile;
    if(bList)
        hFile = CreateFile(szRemindList, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_ARCHIVE, NULL);
    else
        hFile = CreateFile(szRemindItem, GENERIC_WRITE|GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_ARCHIVE, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        DWORD dwBytes = NULL;
        if (!bList)
        {
            if (GetFileSize(hFile, 0) / sizeof SMZDMITEM >= 512)
            {
                SMZDMITEM* lpsi=new SMZDMITEM[256];
                SetFilePointer(hFile, 256 * sizeof SMZDMITEM, 0, FILE_BEGIN);
                ReadFile(hFile, lpsi, 256 * sizeof SMZDMITEM, &dwBytes, 0);
                SetFilePointer(hFile,0, 0, FILE_BEGIN);
                SetEndOfFile(hFile);
                WriteFile(hFile, lpsi, 256 * sizeof SMZDMITEM, &dwBytes, 0);
                delete[]lpsi;
            }
        }		
        SetFilePointer(hFile, 0, 0, FILE_END);
		WriteFile(hFile, si, sizeof SMZDMITEM, &dwBytes, NULL);
        CloseHandle(hFile);
    }
}
void ReadSet()
{
	SetToCurrentPath();
	HANDLE hFile = CreateFile(szRemindSave, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_ARCHIVE, NULL);
    if (hFile!= INVALID_HANDLE_VALUE)
    {
        DWORD dwBytes;
        ReadFile(hFile, &RemindSave, sizeof RemindSave, &dwBytes, NULL);

        riSize = GetFileSize(hFile, NULL) - sizeof RemindSave;
        if (riSize)
        {            
            if (lpRemindItem != NULL)
                delete[]lpRemindItem;
            lpRemindItem = (REMINDITEM*)new BYTE[riSize];
            ReadFile(hFile, lpRemindItem, riSize, &dwBytes, NULL);
        }
        CloseHandle(hFile);
    }

}
void WriteSet(REMINDITEM*lpRI)
{
	SetToCurrentPath();
    if (lpRI)
    {
        HANDLE hFile = CreateFile(szRemindSave, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_ARCHIVE, NULL);
        if (hFile != INVALID_HANDLE_VALUE)
        {
			DWORD dwBytes = NULL;
			WriteFile(hFile, &RemindSave, sizeof RemindSave, &dwBytes, NULL);
            SetFilePointer(hFile, 0, NULL, FILE_END);
            WriteFile(hFile, lpRI, sizeof REMINDITEM, &dwBytes, NULL);
            CloseHandle(hFile);
        }
    }
    else
    {
        HANDLE hFile = CreateFile(szRemindSave, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_ARCHIVE, NULL);
        if (hFile!= INVALID_HANDLE_VALUE)
        {
            DWORD dwBytes = NULL;
            WriteFile(hFile, &RemindSave, sizeof RemindSave, &dwBytes, NULL);
            int n = riSize / sizeof REMINDITEM;
            for (int i = 0; i < n; i++)
            {
                if (lpRemindItem[i].szKey[0] != L'\0' || lpRemindItem[i].szMemberID[0] != L'\0')
                    WriteFile(hFile, &lpRemindItem[i], sizeof REMINDITEM, &dwBytes, NULL);
            }
            CloseHandle(hFile);

        }
    }
}
void HttpRequest(const WCHAR* wDomain, const WCHAR* wRequest, const WCHAR* wReferer, WCHAR * wCookie, WCHAR* wOutBuffer, int iButterSize, BOOL bPost=FALSE, const WCHAR* szPost = NULL, BOOL bGBK = FALSE, INTERNET_PORT iPort=INTERNET_DEFAULT_HTTPS_PORT,const WCHAR *wContent=NULL)//http发送与接收
{
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL, hConnect = NULL, hRequest = NULL;
    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(szUserAgent, WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, NULL);
    if (rovi.dwMajorVersion == 6 && rovi.dwMinorVersion == 1)//WIN 7 开启TLS1.2
    {
        DWORD flags = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
        WinHttpSetOption(hSession, WINHTTP_OPTION_SECURE_PROTOCOLS, &flags, sizeof(flags));
    }
    // Specify an HTTP server.
    if (hSession)
    {
        hConnect = WinHttpConnect(hSession, wDomain, iPort, 0);
    }
    // Create an HTTP request handle.
    if (hConnect)
    {
        if (bPost)
            hRequest = WinHttpOpenRequest(hConnect, L"POST", wRequest, NULL, L"", WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        else
            hRequest = WinHttpOpenRequest(hConnect, L"GET", wRequest, NULL, L"", WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    }
    if (rovi.dwMajorVersion == 6 && rovi.dwMinorVersion == 1)//WIN 7 开启TLS1.2
    {
        DWORD dwSecFlag = SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
            SECURITY_FLAG_IGNORE_UNKNOWN_CA |
            SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwSecFlag, sizeof(dwSecFlag));
    }
    WCHAR szCookie[4096] = L"Cookie: ";
    if (wCookie)
    {        
        lstrcat(szCookie, wCookie);
        WinHttpAddRequestHeaders(hRequest, szCookie, lstrlen(szCookie), WINHTTP_ADDREQ_FLAG_ADD);
    }
    if (wReferer)
    {
        WCHAR szReferer[4096] = L"Referer: ";
        lstrcat(szReferer, wReferer);
        WinHttpAddRequestHeaders(hRequest, szReferer, lstrlen(szReferer), WINHTTP_ADDREQ_FLAG_ADD);
    }
    
    WCHAR szContentType[1024] = L"Content-Type: ";
    if (wContent)
        lstrcat(szContentType, wContent);
    else
        lstrcat(szContentType, L"application/x-www-form-urlencoded;charset=utf-8");
    WinHttpAddRequestHeaders(hRequest, szContentType, lstrlen(szContentType), WINHTTP_ADDREQ_FLAG_ADD);
    // Send a request.
    if (hRequest)
    {
        if (bPost && szPost != NULL)//有POST
        {
            int lSize = lstrlen(szPost);
            char* szUTF8 = new char[lSize * 2];
            if (bGBK)
                ::WideCharToMultiByte(CP_ACP, NULL, szPost, -1, szUTF8, lSize*2, NULL, NULL);
            else
                ::WideCharToMultiByte(CP_UTF8, NULL, szPost, -1, szUTF8, lSize*2, NULL, NULL);
            bResults = WinHttpSendRequest(hRequest, 0, 0, szUTF8, (DWORD)strlen(szUTF8),(DWORD)strlen(szUTF8), 0);
            delete[]szUTF8;
        }
        else
            bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

    }

    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    DWORD dErr = GetLastError();
    // Keep checking for data until there is nothing left.
    size_t i = 0;
    char* pszOutBuffer = new char[iButterSize];
    ZeroMemory(pszOutBuffer, iButterSize);
    if (bResults)
    {
        do
        {
            dwSize = 0;
            WinHttpQueryDataAvailable(hRequest, &dwSize);
            if (!dwSize)
                break;
            if (int(i + dwSize) > iButterSize)
                dwSize = iButterSize - (DWORD)i;
            if (WinHttpReadData(hRequest, (LPVOID)&pszOutBuffer[i], dwSize, &dwDownloaded))
            {
                i = strlen(pszOutBuffer);
            }
            if (!dwDownloaded)
                break;
        } while (dwSize != 0);
        char* cCharset = xstrstr(pszOutBuffer, "gbk");
        if (cCharset == NULL)
            cCharset = xstrstr(pszOutBuffer, "gb2312");
        char* cHead = xstrstr(pszOutBuffer, "/head");
        if (cCharset)
        {
            if (cCharset < cHead)
                MultiByteToWideChar(CP_ACP, 0, pszOutBuffer, -1, wOutBuffer, iButterSize);
            else
                MultiByteToWideChar(CP_UTF8, 0, pszOutBuffer, -1, wOutBuffer, iButterSize);
        }
        else
            MultiByteToWideChar(CP_UTF8, 0, pszOutBuffer, -1, wOutBuffer, iButterSize);
    }
    delete[] pszOutBuffer;

    if (wCookie)
    {
        DWORD dwIndex = 0;
        WCHAR nCookie[CookieSize];
        BOOL bQuerySizeResult;
        dwSize = CookieSize * 2;
        BOOL bSetCookie = FALSE;
        do
        {
            bQuerySizeResult = WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_SET_COOKIE, WINHTTP_HEADER_NAME_BY_INDEX, nCookie, &dwSize, &dwIndex);
            if (bQuerySizeResult)
            {
                bSetCookie = TRUE;
                WCHAR* wEnd = lstrstr(nCookie, L"; ");
                if (wEnd)
                    wEnd[0] = L'\0';
                lstrcpy(wCookie, nCookie);
                lstrcat(wCookie, L"; ");
                WCHAR* wEqu = lstrstr(nCookie, L"=");
                if (wEqu)
                {
                    wEqu[0] = L'\0';
                    LPWSTR  cStart = szCookie + 8;
                    while (cStart)
                    {
                        LPWSTR cValue = lstrstr(cStart, L"=");
                        if (cValue > cStart && cValue != NULL)
                        {
                            cValue[0] = L'\0';
                            LPWSTR cName = cStart;
                            cValue += 1;
                            cStart = lstrstr(cValue, L"; ");
                            if (cStart != NULL)
                            {
                                cStart[0] = L'\0';
                                cStart += 2;
                            }
                            if (lstrcmp(nCookie, cName) != 0)
                            {
                                lstrcat(wCookie, cName);
                                lstrcat(wCookie, L"=");
                                lstrcat(wCookie, cValue);
                                if (cStart != NULL)
                                    lstrcat(wCookie, L"; ");
                            }
                        }
                        else
                            cStart = NULL;
                    }
                    lstrcpy(szCookie + 8, wCookie);
                }

                //            BOOL bRet = WinHttpAddRequestHeaders(hRequest, szCookie, -1, WINHTTP_ADDREQ_FLAG_REPLACE);
                /*
                                        WCHAR szCookie[4096] = L"Cookie: ";
                                        lstrcat(szCookie, nCookie);
                                        BOOL bRet = WinHttpAddRequestHeaders(hRequest, szCookie, lstrlen(szCookie), WINHTTP_ADDREQ_FLAG_ADD);
                */
                //                bGetCookie=WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_COOKIE, WINHTTP_HEADER_NAME_BY_INDEX, nCookie, &dwSize, &dwIndex);            
            }
        } while (bQuerySizeResult);
        /*
            if (bSetCookie)
            {
                dwIndex = 0;
                dwSize = CookieSize;
                WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_FLAG_REQUEST_HEADERS | WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, nCookie, &dwSize, WINHTTP_NO_HEADER_INDEX);
                WCHAR* wCookieStart = lstrstr(nCookie, L"Cookie: ");
                if (wCookieStart)
                {
                    wCookieStart += 8;
                    WCHAR* wCookieEnd = lstrstr(wCookieStart, L"\r\n");
                    wCookieEnd[0] = L'\0';
                    lstrcpy(wCookie, wCookieStart);
                }
            }
        */
        //    dwSize = CookieSize * 2;
        //        WinHttpQueryHeaders(hRequest,WINHTTP_QUERY_RAW_HEADERS_CRLF,WINHTTP_HEADER_NAME_BY_INDEX,nCookie, &dwSize,WINHTTP_NO_HEADER_INDEX);

        //    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_FLAG_REQUEST_HEADERS | WINHTTP_QUERY_RAW_HEADERS_CRLF, L"Cookie", nCookie, &dwSize, WINHTTP_NO_HEADER_INDEX);
    }
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
}
/*
BOOL SendServerJ()
{
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL, hConnect = NULL, hRequest = NULL;
    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"ServerJ", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, NULL);
    // Specify an HTTP server.
    if (hSession)
        hConnect = WinHttpConnect(hSession, L"sctapi.ftqq.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    WCHAR szGet[1024] = L"/";
    lstrcat(szGet,L"SCT152372TQlJTExCGuU63HYmj8Uargtjb");
    lstrcat(szGet,L".send");
    // Create an HTTP request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"POST", szGet, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);

    // Send a request.
    if (hRequest)
    {
        LPCWSTR header = L"Content-type: application/x-www-form-urlencoded/r/n";
        DWORD ret = WinHttpAddRequestHeaders(hRequest, header, lstrlen(header), WINHTTP_ADDREQ_FLAG_ADD);
        WCHAR szBody[2048] = L"{\"title\": 3333,\n \"desp\": 6666 \n}";
        DWORD dwByte = 0;
        char szUTF8[2048]={0};
        ::WideCharToMultiByte(CP_UTF8, NULL, szBody, int(wcslen(szBody)), szUTF8, 2048, NULL, NULL);
        bResults = WinHttpSendRequest(hRequest, 0, 0, szUTF8, strlen(szUTF8), strlen(szUTF8), 0);
    }
    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);
	char pszOutBuffer[2048];
	int i = 0;
	if (bResults)
	{
		do
		{
			dwSize = 0;
			WinHttpQueryDataAvailable(hRequest, &dwSize);
			if (!dwSize)
				break;
			if (i + dwSize > 2048)
				dwSize = 2048 - i;
			if (WinHttpReadData(hRequest, (LPVOID)&pszOutBuffer[i], dwSize, &dwDownloaded))
			{
				i = strlen(pszOutBuffer);
			}
			if (!dwDownloaded)
				break;
		} while (dwSize != 0);
	}
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    return TRUE;
}
BOOL SendIYUU(wchar_t* szTOKEN, wchar_t* szTitle, wchar_t* szContent, wchar_t* szUrl, float fPrice, wchar_t* szBusiness, wchar_t* szImg)
{
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL, hConnect = NULL, hRequest = NULL;
    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(szUserAgent, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, NULL);
    // Specify an HTTP server.
    if (hSession)
        hConnect = WinHttpConnect(hSession, L"iyuu.cn", INTERNET_DEFAULT_HTTPS_PORT, 0);
    WCHAR szGet[1024]=L"/";
    lstrcat(szGet, szTOKEN);
    lstrcat(szGet, L".send");
    / *
        lstrcat(szGet, L"?appToken=AT_YGOXF3ZtPSkz5lkxhFUZ5ZkHOgrkKSdG&content=");
        lstrcat(szGet, szTitle);
        lstrcat(szGet, L"&uid=UID_XdNax8pCAEVtiAYu0ZmHNGq9r1Ma&url=");
        lstrcat(szGet, szUrl);
    * /
    // Create an HTTP request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"POST", szGet, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);

    // Send a request.
    if (hRequest)
    {
        LPCWSTR header = L"Content-type: application/x-www-form-urlencoded";
        DWORD ret = WinHttpAddRequestHeaders(hRequest, header, lstrlen(header), WINHTTP_ADDREQ_FLAG_ADD);
        WCHAR szBody[2048] = L"{\n \"text\": \"33333\", \"desp\": \"666\" \n}";
		DWORD dwByte = 0;
		char szUTF8[2048]={0};
		::WideCharToMultiByte(CP_UTF8, NULL, szBody, int(wcslen(szBody)), szUTF8, 2048, NULL, NULL);
		bResults = WinHttpSendRequest(hRequest, 0, 0, szUTF8, strlen(szUTF8), strlen(szUTF8), 0);

    }
    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);
	char pszOutBuffer[2048];
	int i = 0;
	if (bResults)
	{
		do
		{
			dwSize = 0;
			WinHttpQueryDataAvailable(hRequest, &dwSize);
			if (!dwSize)
				break;
			if (i + dwSize > 2048)
				dwSize = 2048 - i;
			if (WinHttpReadData(hRequest, (LPVOID)&pszOutBuffer[i], dwSize, &dwDownloaded))
			{
				i = strlen(pszOutBuffer);
			}
			if (!dwDownloaded)
				break;
		} while (dwSize != 0);
	}
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    return TRUE;
}
*/
BOOL SendBark(wchar_t* szBarkUrl,wchar_t* szBarkSound,wchar_t* szTitle, wchar_t* szContent, wchar_t* szUrl, wchar_t* szImg)
{
    WCHAR wDomain[128];
    WCHAR *wDomainLeft = lstrstr(szBarkUrl, L"//");
    UINT uPort = INTERNET_DEFAULT_HTTPS_PORT;
    if (wDomainLeft)
    {
        wDomainLeft += 2;
    }
    else
        wDomainLeft = szBarkUrl;
    WCHAR* wDomainRight = lstrstr(wDomainLeft, L":");
    if (wDomainRight)
    {
        uPort = my_wtoi(wDomainRight+1);
    }
    else
        wDomainRight= lstrstr(wDomainLeft, L"/");
    lstrcpyn(wDomain, wDomainLeft, int(wDomainRight - wDomainLeft + 1));
    WCHAR wGet[64];
    WCHAR* wGetLeft = lstrstr(wDomainRight - 1, L"/");
    if (wGetLeft)
    {
        lstrcpy(wGet, wGetLeft);
    }
    WCHAR wOutBuffer[2048];
	WCHAR szBody[2048];
	wsprintf(szBody, L"{\n\"body\": \"%s\",\n	\"title\": \"%s\",\n \"badge\": 1,\n \"category\": \"category\",\n \"sound\": \"%s\",\n \"icon\": \"https://%s\",\n \"url\": \"%s\"\n }", szContent, szTitle, szBarkSound, szImg, szUrl);
    HttpRequest(wDomain, wGet, NULL, NULL, wOutBuffer, 2046, TRUE, szBody, FALSE, uPort, L"application/json");
    return TRUE;
}

BOOL GetWeChatToken(wchar_t* corpid, wchar_t *corpsecret,wchar_t * access_token)
{
    access_token[0] = L'~';    
	WCHAR szGet[1024] = L"/cgi-bin/gettoken?corpid=";
	lstrcat(szGet, corpid);
    lstrcat(szGet, L"&corpsecret=");
    lstrcat(szGet, corpsecret);
    WCHAR szOutBuffer[2048] = { 0 };
    HttpRequest(L"qyapi.weixin.qq.com", szGet, NULL, NULL, szOutBuffer, 2046);
    WCHAR *cToken = lstrstr(szOutBuffer, L"access_token");
    if (cToken)
    {
        WCHAR* cTokenLeft = lstrstr(cToken + 14, L"\"");
        if (cTokenLeft)
        {
            cTokenLeft += 1;
            WCHAR* cTokenRight = lstrstr(cTokenLeft, L"\"");
            if (cTokenRight)
            {
                cTokenRight[0] = L'\0';
                lstrcpy(access_token, cTokenLeft);
            }
        }
    }
	return TRUE;
}

BOOL SendWeChatPusher(wchar_t* uid, wchar_t* szTitle, wchar_t* szContent, wchar_t* szUrl, wchar_t* szImg)
{
    WCHAR szGet[1024] = L"/cgi-bin/message/send?access_token=";
    lstrcat(szGet, lpRemindData->szWeChatToken);
    WCHAR szBody[2048];
    wsprintf(szBody, L"{\n\"touser\": \"%s\",\n\"msgtype\": \"news\",\n	\"agentid\": %s,\n	\"news\" : {\n	\"articles\": [{\n	\"title\": \"%s\",\n \"description\": \"%s\",\n \"url\": \"%s\",\n \"picurl\": \"https://%s\"\n }]\n},\n}",
        RemindSave.szWeChatUserID, RemindSave.szWeChatAgentId, szTitle, szContent, szUrl, szImg);
    WCHAR wOutBuffer[2048];
    HttpRequest(L"qyapi.weixin.qq.com", szGet, NULL, NULL, wOutBuffer, 2046, TRUE, szBody, FALSE, INTERNET_DEFAULT_HTTPS_PORT, L"application/json");
    if (lstrstr(wOutBuffer, L"access_token"))
    {
        if (lpRemindData->szWeChatToken[0] != L'~')
        {
            GetWeChatToken(RemindSave.szWeChatID, RemindSave.szWeChatSecret, lpRemindData->szWeChatToken);
            SendWeChatPusher(uid, szTitle, szContent, szUrl, szImg);
        }
        return FALSE;
    }
    else
        return TRUE;
}
BOOL SendDingDing(wchar_t* access_token, wchar_t* szTitle, wchar_t* szContent, wchar_t* szUrl,wchar_t* szImg)
{
	WCHAR szGet[1024] = L"/robot/send?access_token=";
	lstrcat(szGet, access_token);
	WCHAR szBody[2048];
    wsprintf(szBody,L"{\n \"msgtype\": \"link\",\n \"link\": {\n \"text\": \"%s\",\n \"title\": \"%s\",\n \"picUrl\": \"https://%s\",\n \"messageUrl\": \"%s\"\n }\n}", szContent, szTitle, szImg, szUrl);
    WCHAR wOutBuffer[2048];
    HttpRequest(L"oapi.dingtalk.com", szGet, NULL, NULL, wOutBuffer, 2046, TRUE, szBody, FALSE, INTERNET_DEFAULT_HTTPS_PORT, L"application/json");
	return TRUE;
}

BOOL SendWxPusher(wchar_t* uid, wchar_t* szTitle, wchar_t* szContent, wchar_t* szUrl, wchar_t* szImg)
{
    WCHAR szGet[1024] = L"/api/send/message";
    WCHAR szBody[2048];
    wsprintf(szBody, L"\n{\n\"appToken\":\"%s\",\n\"content\":\"<img src=https://%s /> <font size=4> <br /> %s </font> \",\n\"summary\":\"%s\",\n\"contentType\":2,\n\"topicIds\":[123],\n\"uids\":[\"%s\"],\n\"url\":\"%s\"\n}\n",
        szWxPusherToken, szImg, szContent, szTitle, uid, szUrl);
    WCHAR wOutBuffer[2048];
    HttpRequest(L"wxpusher.zjiecode.com", szGet, NULL, NULL, wOutBuffer, 2046, TRUE, szBody, FALSE, INTERNET_DEFAULT_HTTPS_PORT, L"application/json");
    return TRUE;
}
void GetMember(WCHAR*szMember,WCHAR*szMemberID)
{
	WCHAR szGet[1024] = L"/?c=zhiyou&v=b&s=";
	WCHAR szUrlCode[1024];
	UrlUTF8(szMember, szUrlCode);
	lstrcat(szGet, szUrlCode);
	WCHAR *wOutBuffer= new WCHAR[NETPAGESIZE];
    WCHAR wCookie[CookieSize] = L"ssmx_ab=mxss38";
	HttpRequest(L"search.smzdm.com", szGet, NULL, wCookie, wOutBuffer, NETPAGESIZE-2, FALSE);
	WCHAR* wMember = lstrstr(wOutBuffer, L"member/");
	if (wMember)
	{
		wMember += 7;
		WCHAR* wMemberRight = lstrstr(wMember, L"/");
		if (wMemberRight && wMemberRight - wMember < 12)
		{
			wMemberRight[0] = L'\0';
            lstrcpyn(szMemberID, wMember, 12);
		}
	}
    delete[]wOutBuffer;
}
BOOL isPushed(REMINDITEM* lpRI, UINT id)
{
    for (int i=0;i<38;i++)
    {
        if (lpRI->oldID[i] == id)
            return TRUE;
    }
    return FALSE;
}
void SetOldPushed(REMINDITEM* lpRI, UINT id)
{
    if (lpRI->n > 37)
        lpRI->n = 0;
    lpRI->oldID[lpRI->n] = id;
    lpRI->n += 1;
}
BOOL GetMemberZhiStarTalk(WCHAR* wUrl, UINT* uZhi, UINT* uBuZhi, UINT* uStar, UINT* uTalk)
{
    BOOL bPost = FALSE;
    if (lstrstr(wUrl, L"post"))
        bPost = TRUE;
    WCHAR* wHost = lstrstr(wUrl, L":");
    if (wHost)
        wHost += 3;
    else
        wHost = wUrl;
    WCHAR* wUrlPath = lstrstr(wHost, L"/");
    WCHAR szHost[128];
    lstrcpyn(szHost, wHost, int(wUrlPath - wHost + 1));
    WCHAR* wOutBuffer = new WCHAR[NETPAGESIZE];
    HttpRequest(szHost, wUrlPath, NULL, NULL, wOutBuffer, NETPAGESIZE-2, FALSE);
    WCHAR* wStart = wOutBuffer;// xstrstr(pszOutBuffer, "icon-thumb-up-o-thin");
    if (wStart)
    {
        WCHAR* wZhi;
        if (bPost)
            wZhi = lstrstr(wStart, L"feed-number");
        else
            wZhi = lstrstr(wStart, L"rating_worthy_num");
        if (wZhi)
        {
            WCHAR* wZhiLeft = lstrstr(wZhi, L">");
            if (wZhiLeft)
            {
                wZhiLeft += 1;
                *uZhi = my_wtoi(wZhiLeft);
            }
        }
        if (!bPost)
        {
            WCHAR* wBuZhi = lstrstr(wStart, L"rating_unworthy_num");
            if (wBuZhi)
            {
                WCHAR* wBuZhiLeft = lstrstr(wBuZhi, L">");
                if (wBuZhiLeft)
                {
                    wBuZhiLeft += 1;
                    *uBuZhi = my_wtoi(wBuZhiLeft);
                }
            }
        }
        WCHAR* wStar = lstrstr(wStart, L"\"icon-star-o");
        if (wStar)
        {
            WCHAR* wStarLeft = lstrstr(wStar, L"span");
            if (wStarLeft)
            {
                wStarLeft = lstrstr(wStarLeft, L">");
                if (wStarLeft)
                {
                    wStarLeft += 1;
                    *uStar = my_wtoi(wStarLeft);
                }
            }
        }
        WCHAR* wTalk;
        if (bPost)
            wTalk = lstrstr(wStart, L"icon-comment-o");
        else
            wTalk = lstrstr(wStart, L"icon-comment-o\"");
        if (wTalk)
        {
            WCHAR* wTalkLeft;
            if (bPost)
                wTalkLeft = lstrstr(wTalk, L"em>");
            else
                wTalkLeft = lstrstr(wTalk, L"an>");
            if (wTalkLeft)
            {
                wTalkLeft += 3;
                *uTalk = my_wtoi(wTalkLeft);
            }
        }
    }
    delete[]wOutBuffer;
    return TRUE;
}
DWORD WINAPI GetZhiThreadProc(PVOID pParam)//获取网站数据线程
{
    UINT i = (UINT)pParam;
        WCHAR szUrl[129];
        UINT uZhi = 0, uBuZhi = 0, uStar = 0, uTalk = 0;
        ListView_GetItemText(hList, i, 10, szUrl, 128);
        GetMemberZhiStarTalk(szUrl, &uZhi, &uBuZhi, &uStar, &uTalk);
        wsprintf(szUrl,L"%d", uZhi);
        ListView_SetItemText(hList, i, 4, szUrl);
		wsprintf(szUrl, L"%d", uBuZhi);
		ListView_SetItemText(hList, i, 5, szUrl);
		wsprintf(szUrl,L"%d", uStar);
		ListView_SetItemText(hList, i, 6, szUrl);
		wsprintf(szUrl,L"%d", uTalk);
		ListView_SetItemText(hList, i, 7, szUrl);
    return 0;
}
int SignKaFan(WCHAR* wCookie)
{
    WCHAR* wOutBuffer = new WCHAR[1024 * 1024];
    HttpRequest(L"bbs.kafan.cn", L"/", L"https://bbs.kafan.cn/", wCookie, wOutBuffer, 1024 * 1024-2, FALSE);
    if (lstrstr(wOutBuffer, L"找回密码"))
    {
        WriteLog(L"Cookie失效    卡饭论坛", TRUE);
        delete[]wOutBuffer;
        return -99;
    }
    else
    {
        WCHAR* wStart = lstrstr(wOutBuffer, L"pper_a");
        if (wStart)
        {
            WCHAR* wLink = lstrstr(wStart, L"formhash");
            if (wLink)
            {
                WCHAR* wLinkEnd = lstrstr(wLink, L"\"");
                if (wLinkEnd)
                {
                    wLinkEnd[0] = L'\0';
                    WCHAR szLink[128] = L"/plugin.php?id=dsu_amupper&ppersubmit=true&";
                    lstrcat(szLink, wLink);
                    HttpRequest(L"bbs.kafan.cn", szLink, L"https://bbs.kafan.cn/", wCookie, wOutBuffer, 1024 * 1024-2, FALSE);
                }
            }
        }
        WriteLog(L"签到    卡饭论坛", FALSE);
    }
    delete[]wOutBuffer;
    return TRUE;
}
/*
int Sign52pojie(WCHAR* wCookie)
{
    WCHAR* wOutBuffer = new WCHAR[1024 * 1024];
    HttpRequest(L"www.52pojie.cn", L"/home.php?mod=task&do=apply&id=2&referer=%2F", L"https://www.52pojie.cn/", wCookie, wOutBuffer, 1024 * 1024, FALSE);
    HttpRequest(L"www.52pojie.cn", L"/CSPDREL2hvbWUucGhwP21vZD10YXNr?wzwscspd=MC4wLjAuMA==", L"https://www.52pojie.cn/home.php?mod=task&do=apply&id=2&referer=%2F", wCookie, wOutBuffer, 1024 * 1024, FALSE);
    HttpRequest(L"www.52pojie.cn", L"/home.php?mod=task&do=apply&id=2&referer=%2F", L"https://www.52pojie.cn/home.php?mod=task&do=apply&id=2&referer=%2F", wCookie, wOutBuffer, 1024 * 1024, FALSE);
    if (lstrstr(wOutBuffer, L"要先登录"))
    {
        WriteLog(L"Cookie失效    吾爱破解", TRUE);
        return -99;
    }
    else
    {
        WriteLog(L"签到成功    吾爱破解", FALSE);
    }
    delete[]wOutBuffer;
    return TRUE;
}
*/
int SignSeHuaTang(WCHAR* wCookie)
{
    WCHAR* wOutBuffer = new WCHAR[1024 * 1024];
    HttpRequest(L"www.sehuatang.org", L"/plugin.php?id=dd_sign&mod=sign", L"https://www.sehuatang.org/", wCookie, wOutBuffer, 1024 * 1024-2, FALSE);
    if (lstrstr(wOutBuffer, L"尚未登录"))
    {
        WriteLog(L"Cookie失效    98堂", TRUE);
        delete[]wOutBuffer;
        return -99;
    }
    else
    {
        WCHAR* wStart = lstrstr(wOutBuffer, L"ajaxpost");
        if (wStart)
        {
            WCHAR* wLink = lstrstr(wStart, L"signhash");
            if (wLink)
            {
                WCHAR* wLinkRight = lstrstr(wLink, L"\"");
                if (wLinkRight)
                {
                    wLinkRight[0] = L'\0';
                    WCHAR* wFormhash = lstrstr(wLinkRight + 1, L"value");
                    if (wFormhash)
                    {
                        wFormhash += 7;
                        WCHAR* wFormhashRight = lstrstr(wFormhash, L"\"");
                        if (wFormhashRight)
                        {
                            wFormhashRight[0] = L'\0';
                            WCHAR* wSigntoken = lstrstr(wFormhashRight + 1, L"value");
                            if (wSigntoken)
                            {
                                wSigntoken += 7;
                                WCHAR* wSigntokenRight = lstrstr(wSigntoken, L"\"");
                                if (wSigntokenRight)
                                {
                                    wSigntokenRight[0] = L'\0';
                                    WCHAR* wSecqaahash = lstrstr(wSigntokenRight + 1, L"value");
                                    if (wSecqaahash)
                                    {
                                        wSecqaahash += 7;
                                        WCHAR* wSecqaahashRight = lstrstr(wSecqaahash, L"\"");
                                        if (wSecqaahashRight)
                                        {
                                            wSecqaahashRight[0] = L'\0';
                                            WCHAR szPost[1024];
                                            WCHAR wNumBuffer[1024];
//                                            WCHAR szHome[1024];
                                            //                                            wsprintf(szHome, L"/home.php?mod=spacecp&ac=pm&op=checknewpm&rand=%s");
                                            //                                                                                        HttpRequest(L"www.sehuatang.org", L"", szHome, wCookie, wNumBuffer, 1024 * 1024, FALSE);
                                            HttpRequest(L"www.sehuatang.org", L"/misc.php?mod=secqaa&action=update&idhash=qS0&0.8888888888888888", L"https://www.sehuatang.org/plugin.php?id=dd_sign&mod=sign", wCookie, wNumBuffer, 1024 * 1024-2, FALSE);
                                            WCHAR* wNum = lstrstr(wNumBuffer, L" = ?");
                                            if (wNum)
                                            {
                                                if (wNum)
                                                {
                                                    wNum[0] = L'\0';
                                                    while (wNum[0] != L'\'')
                                                    {
                                                        wNum--;
                                                    }
                                                    WCHAR* wNum1 = wNum += 1;
                                                    while (wNum[0] != L' ')
                                                    {
                                                        wNum++;
                                                    }
                                                    wNum[0] = L'\0';
                                                    WCHAR wOperator = wNum[1];
                                                    WCHAR* wNum2 = wNum + 3;
                                                    int iSecanswer = 0;
                                                    if (wOperator == L'+')
                                                        iSecanswer = my_wtoi(wNum1) + my_wtoi(wNum2);
                                                    else
                                                        iSecanswer = my_wtoi(wNum1) - my_wtoi(wNum2);
                                                    WCHAR szLink[1024] = L"/plugin.php?id=dd_sign&mod=sign&signsubmit=yes&";
                                                    lstrcat(szLink, wLink);
                                                    lstrcat(szLink, L"&inajax=1");
                                                    wsprintf(szPost, L"formhash=%s&signtoken=%s&secqaahash=qS0&secanswer=%d", wFormhash, wSigntoken, iSecanswer);
                                                    HttpRequest(L"www.sehuatang.org", szLink, L"https://www.sehuatang.org/plugin.php?id=dd_sign&mod=sign", wCookie, wOutBuffer, 1024 * 1024-2, TRUE, szPost);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        WriteLog(L"签到    98堂", FALSE);
    }
    delete[]wOutBuffer;
    return TRUE;
}

int SignPCBeta(WCHAR* wCookie)
{
    WCHAR* wOutBuffer = new WCHAR[1024 * 1024];
    HttpRequest(L"i.pcbeta.com", L"/home.php?mod=task&do=apply&id=149", L"https://i.pcbeta.com/", wCookie, wOutBuffer, 1024 * 1024-2, FALSE);
    if (lstrstr(wOutBuffer, L"要先登录"))
    {
        WriteLog(L"Cookie失效    远景论坛", TRUE);
        delete[]wOutBuffer;
        return -99;
    }
    else
    {
        WriteLog(L"签到    远景论坛", FALSE);
    }
    HttpRequest(L"i.pcbeta.com", L"/home.php?mod=task&item=new", L"https://i.pcbeta.com/", wCookie, wOutBuffer, 1024 * 1024-2, FALSE);
    WCHAR* wApply = lstrstr(wOutBuffer, L"do=apply");
    if (wApply)
    {
        WCHAR* wLink = lstrstr(wApply, L"id=");
        if (wLink)
        {
            wLink += 3;
            WCHAR* wLinkEnd = lstrstr(wLink, L"\"");
            if (wLinkEnd)
            {
                wLinkEnd[0] = L'\0';
                WCHAR wID[8];
                lstrcpy(wID, wLink);
                WCHAR wNew[256] = L"/home.php?mod=task&do=apply&id=";
                lstrcat(wNew, wID);
                HttpRequest(L"i.pcbeta.com", wNew, L"https://i.pcbeta.com/", wCookie, wOutBuffer, 1024 * 1024-2, FALSE);
                WCHAR wNow[256] = L"/home.php?mod=task&do=view&id=";
                lstrcat(wNow, wID);
                HttpRequest(L"i.pcbeta.com", wNow, L"https://i.pcbeta.com/", wCookie, wOutBuffer, 1024 * 1024-2, FALSE);
                WCHAR* wIS = lstrstr(wOutBuffer, L"在“");
                if (wIS)
                {
                    WCHAR* wOut = lstrstr(wIS, L"/view");
                    if (wOut)
                    {
                        WCHAR* wOutEnd = lstrstr(wOut, L"\"");
                        if (wOutEnd)
                        {
                            wOutEnd[0] = L'\0';
                            WCHAR wReferer[1024] = L"https://bbs.pcbeta.com";
                            lstrcat(wReferer, wOut);
                            HttpRequest(L"bbs.pcbeta.com", wOut, L"https://i.pcbeta.com/", wCookie, wOutBuffer, 1024 * 1024-2, FALSE);
                            WCHAR* wPost = lstrstr(wOutBuffer, L"fastpostform");
                            if (wPost)
                            {
                                FILETIME ft;
                                SYSTEMTIME st;
                                GetSystemTime(&st);
                                SystemTimeToFileTime(&st, &ft);
//                                LONGLONG nLL;
                                ULARGE_INTEGER ui;
                                ui.LowPart = ft.dwLowDateTime;
                                ui.HighPart = ft.dwHighDateTime;
                                //                                                                nLL = (ft.dwHighDateTime << 32) + ft.dwLowDateTime;
#if defined _M_IX86
                                UINT64 pt64;
                                UINT32 ys;
                                uint64_div_uint32(ui.QuadPart - 116444736000000000, 10000000, &pt64, &ys);
                                time_t pt = (long)pt64;
#else
                                time_t pt = (long)((LONGLONG)(ui.QuadPart - 116444736000000000) / 10000000);
#endif

                                WCHAR* wLink = lstrstr(wPost, L"=\"");
                                if (wLink)
                                {
                                    wLink += 2;
                                    WCHAR* wLinkEnd = lstrstr(wLink, L"\"");
                                    if (wLinkEnd)
                                    {
                                        wLinkEnd[0] = L'\0';
                                        WCHAR* wFormhashStart = lstrstr(wLinkEnd + 1, L"formhash");
                                        if (wFormhashStart)
                                        {
                                            WCHAR* wFormhash = lstrstr(wFormhashStart, L"=\"");
                                            if (wFormhash)
                                            {
                                                wFormhash += 2;
                                                WCHAR* wFormhashEnd = lstrstr(wFormhash, L"\"");
                                                if (wFormhashEnd)
                                                {
                                                    wFormhashEnd[0] = L'\0';
                                                    WCHAR szLink[1024] = L"/";
                                                    do
                                                    {
                                                        wLinkEnd = lstrstr(wLink, L"amp;");
                                                        if (wLinkEnd)
                                                            wLinkEnd[0] = L'\0';
                                                        lstrcat(szLink, wLink);
                                                        wLink = wLinkEnd + 4;
                                                    } while (wLinkEnd);
                                                    lstrcat(szLink, L"&inajax=1");
                                                    WCHAR szPost[1024] = L"message=SmzdmRemind%C7%A9%B5%BD%A3%A1&posttime=";
                                                    WCHAR szPrint[1024];
                                                    wsprintf(szPrint, L"%d&formhash=%s&subject=&usesig=1", pt, wFormhash);
                                                    lstrcat(szPost, szPrint);
                                                    HttpRequest(L"bbs.pcbeta.com", szLink, wReferer, wCookie, wOutBuffer, 1024 * 1024-2, TRUE, szPost);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                WCHAR wReceive[1024] = L"/home.php?mod=task&do=draw&id=";
                lstrcat(wReceive, wID);
                HttpRequest(L"i.pcbeta.com", wReceive, L"https://i.pcbeta.com/", wCookie, wOutBuffer, 1024 * 1024-2, FALSE);
            }
        }
    }
    delete[]wOutBuffer;
    return TRUE;
}

int SignMyDigit(WCHAR* wCookie)
{
    WCHAR* wOutBuffer = new WCHAR[1024 * 1024];
    HttpRequest(L"www.mydigit.cn", L"/plugin.php?id=k_misign:sign", L"https://www.mydigit.cn/", wCookie, wOutBuffer, 1024 * 1024-2, FALSE);
    if (lstrstr(wOutBuffer, L"找回密码"))
    {
        WriteLog(L"Cookie失效    数码之家", TRUE);
        delete[]wOutBuffer;
        return -99;
    }
    else
    {
        WCHAR* wLink = lstrstr(wOutBuffer, L"JD_sign");
        if (wLink)
        {
            WCHAR* wLinkLeft = lstrstr(wLink, L"=\"");
            if (wLinkLeft)
            {
                wLinkLeft += 1;
                wLinkLeft[0] = L'/';
                WCHAR* wLinkRight = lstrstr(wLinkLeft, L"\"");
                if (wLinkRight)
                {
                    wLinkRight[0] = L'\0';
                    HttpRequest(L"www.mydigit.cn", wLinkLeft, L"https://www.mydigit.cn/", wCookie, wOutBuffer, 1024 * 1024-2, FALSE);
                }
            }
        }
        WriteLog(L"签到    数码之家", FALSE);
    }
    delete[]wOutBuffer;
    return TRUE;
}
int SignTieba(WCHAR* wCookie)
{
    WCHAR* wOutBuffer = new WCHAR[1024 * 1024];
    HttpRequest(L"tieba.baidu.com", L"/f/like/mylike", L"https://tieba.baidu.com/", wCookie, wOutBuffer, 1024 * 1024-2, FALSE);
    WCHAR* wStart = lstrstr(wOutBuffer, L"/f?kw");
    if (wStart)
    {
        WCHAR* wLinkStart;
        while (wLinkStart = lstrstr(wStart, L"/f?kw"))
        {
            wLinkStart += 6;
            WCHAR* wLinkEnd = lstrstr(wLinkStart, L"\"");
            if (wLinkEnd)
            {
                wLinkEnd[0] = L'\0';
                WCHAR wRequest[1024];
                wsprintf(wRequest, L"/sign/add?ie=utf-8&kw=%s", wLinkStart);
                HttpRequest(L"tieba.baidu.com", wRequest, L"https://tieba.baidu.com/", wCookie, wOutBuffer, 1024 * 1024-2, TRUE);
                Sleep(188);
            }
            wStart = wLinkEnd + 1;
        }
        WriteLog(L"签到    百度贴吧", FALSE);
    }
    else
        WriteLog(L"Cookie失效    百度贴吧", TRUE);
    delete[]wOutBuffer;
    return -1;
}

int SignV2EX(WCHAR* wCookie)
{
    WCHAR* wOutBuffer = new WCHAR[1024 * 1024];
    HttpRequest(L"v2ex.com", L"/mission/daily", L"https://v2ex.com/", wCookie, wOutBuffer, 1024 * 1024-2, FALSE);
    if (lstrstr(wOutBuffer, L"要先登录"))
    {
        WriteLog(L"Cookie失效    V2EX", TRUE);
        delete[]wOutBuffer;
        return -99;
    }
    WCHAR* cLink = lstrstr(wOutBuffer, L"/mission/daily/redeem");
    if (cLink)
    {
        WCHAR* cLinkRight = lstrstr(cLink, L"'");
        if (cLinkRight)
        {
            cLinkRight[0] = L'\0';
            HttpRequest(L"v2ex.com", cLink, L"https://v2ex.com/mission/daily", wCookie, wOutBuffer, 1024 * 1024-2, FALSE);
            return TRUE;
        }
    }
    WriteLog(L"签到    V2EX", FALSE);
    delete[]wOutBuffer;
    return -1;
}
int SignSMZDM(WCHAR* wCookie)
{
    int nDay = -111;
    WCHAR szGet[4096];
    FILETIME ft;
    SYSTEMTIME st;
    GetLocalTime(&st);
    SystemTimeToFileTime(&st, &ft);
//    LONGLONG nLL;
    ULARGE_INTEGER ui;
    ui.LowPart = ft.dwLowDateTime;
    ui.HighPart = ft.dwHighDateTime;
    //    nLL = (ft.dwHighDateTime << 32) + ft.dwLowDateTime;
#if defined _M_IX86
    UINT64 pt64;
    UINT32 ys;
    uint64_div_uint32(ui.QuadPart - 116444736000000000, 10000000, &pt64, &ys);
    time_t pt = (long)pt64;
#else
    time_t pt = (long)((LONGLONG)(ui.QuadPart - 116444736000000000) / 10000000);
#endif
    wsprintf(szGet, L"/user/checkin/jsonp_checkin?callback=jQuery13689&_=%d168", pt);
    WCHAR wOutBuffer[4096];
    HttpRequest(L"zhiyou.smzdm.com", szGet, L"https://www.smzdm.com/", wCookie, wOutBuffer, 4096-2, FALSE);
    WCHAR* wErrorCode = lstrstr(wOutBuffer, L"error_code");
    int iErrorCode = -111;
    if (wErrorCode)
    {
        WCHAR* wECLeft = lstrstr(wErrorCode, L":");
        if (wECLeft)
        {
            wECLeft += 1;
            iErrorCode = my_wtoi(wECLeft);
            if (iErrorCode < 0)
                nDay = iErrorCode;
            else
                nDay = -iErrorCode;
            WCHAR* wCheckinNum = lstrstr(wOutBuffer, L"checkin_num");
            if (wCheckinNum)
            {
                WCHAR* wCheckinNumLeft = lstrstr(wCheckinNum, L":");
                if (wCheckinNumLeft)
                {
                    wCheckinNumLeft += 2;
                    nDay = my_wtoi(wCheckinNumLeft);
                    WriteLog(L"签到    什么值得买", FALSE);
                }
            }
        }
    }
    if (nDay < 0)
        WriteLog(L"Cookie失效    什么值得买", TRUE);
    return nDay;
}
BOOL SearchSMZDM(REMINDITEM* lpRI, BOOL bList, int iPage, BOOL bSmzdmSearch, BOOL bGrey)
{
    WCHAR szGet[1024] = L"/?s=";
    WCHAR szUrlCode[1024];
    BOOL bZhi = FALSE;//是否综合排序推送
    if (lpRI->szMemberID[0] == L'\0')
    {
        UrlUTF8(lpRI->szKey, szUrlCode);
        //	lstrcat(szGet, lpRI->szKey);
        lstrcat(szGet, szUrlCode);
        if (!lpRI->bMemberPost)
            lstrcat(szGet, L"&c=faxian");
        else
            lstrcat(szGet, L"&c=post&f_c=post");
        if (lpRI->iBusiness && !lpRI->bMemberPost)
        {
            lstrcat(szGet, L"&mall_id=");
            WCHAR sz[16];
            wsprintf(sz, L"%d", mIDs[lpRI->iBusiness]);
            lstrcat(szGet, sz);
        }
        if (lpRI->uZhi || lpRI->uBuZhi || lpRI->uPercentage || lpRI->uTalk)
        {
            bZhi = TRUE;
            if (lpRI->uPercentage != 0)
                lstrcat(szGet, L"&f_c=zhi");
        }
        if (bZhi == FALSE || lpRI->bScore == FALSE)
            lstrcat(szGet, L"&order=time&v=b");
        else
            lstrcat(szGet, L"&order=score&v=b");
        if ((lpRI->uMaxPrice != 0 || lpRI->uMinPrice != 0) && !lpRI->bMemberPost)
        {
            lstrcat(szGet, L"&min_price=");
            if (lpRI->uMinPrice != 0)
            {
                WCHAR szPrice[16];
                int p = lpRI->uMinPrice * 100;
                wsprintf(szPrice, L"%d.%2.2d", p / 100, p % 100);
                lstrcat(szGet, szPrice);
            }
            lstrcat(szGet, L"&max_price=");
            if (lpRI->uMaxPrice != 0)
            {
                WCHAR szPrice[16];
                int p = lpRI->uMaxPrice * 100;
                wsprintf(szPrice, L"%d.%2.2d", p / 100, p % 100);
                lstrcat(szGet, szPrice);
            }
        }
    }
    else
    {
        lstrcpy(szGet, L"/member/");
        lstrcat(szGet, lpRI->szMemberID);
        if (lpRI->bMemberPost)
            lstrcat(szGet, L"/article/");
        else
            lstrcat(szGet, L"/baoliao/");
    }
    if (bSmzdmSearch)
    {
        WCHAR szUrl[2048];
        if (lpRI->szMemberID[0] == L'\0')
            lstrcpy(szUrl, L"https://search.smzdm.com");
        else
            lstrcpy(szUrl, L"https://zhiyou.smzdm.com");
        lstrcat(szUrl, szGet);
        ShellExecute(NULL, L"open", szUrl, NULL, NULL, SW_SHOW);
        return TRUE;
    }
    if (iPage)
    {
        WCHAR sz[8];
        if (lpRI->szMemberID[0] == L'\0')
            wsprintf(sz, L"&p=%d", iPage);
        else
            wsprintf(sz, L"/p%d", iPage);
        lstrcat(szGet, sz);
    }
    WCHAR* szOutBuffer = new WCHAR[NETPAGESIZE];
    WCHAR wCookie[CookieSize] = L"ssmx_ab=mxss38";
    if (lpRI->szMemberID[0] == L'\0')
        HttpRequest(L"search.smzdm.com", szGet, NULL, wCookie, szOutBuffer, NETPAGESIZE-2, FALSE);
    else
        HttpRequest(L"zhiyou.smzdm.com", szGet, NULL, wCookie, szOutBuffer, NETPAGESIZE-2, FALSE);
    // Keep checking for data until there is nothing left.
    size_t i = 0;
    DWORD sl = lstrlen(szOutBuffer);
    SMZDMITEM SmzdmItem = { 0 };
    UINT iID = 0;
    WCHAR wID[10] = { 0 };
    //    WCHAR szPrice[8];
    if (bList)
    {
        SendMessage(hList, WM_SETREDRAW, FALSE, FALSE);
        if (iPage == 0)
        {
            DeleteFile(szRemindList);
            ListView_DeleteAllItems(hList);
            ListView_SetItemCount(hList, 81);
        }
    }
    //        	WCHAR szIYUU[] = L"IYUU12087Tbb1266ff7043661f3c1aafadf8952e8d406b9af6";
    //        	SendIYUU(szIYUU, szTitle, szDescripe, szLink, fPrice, szBusiness, szImg);
            //    WCHAR szTime[6];
    SYSTEMTIME st;
    ULONGLONG ft1, ft2;
    GetLocalTime(&st);
    SystemTimeToFileTime(&st, (LPFILETIME)&ft1);
    ft1 -= (ULONGLONG)108000000000;//三小时内
    /*
            if (bOpen == FALSE)
            {
                ft1 -= (ULONGLONG)3600 * 10000000;
            }
            else
            {
                ft2 = iTimes[RemindSave.iTime];
                ft1 -= ft2 * 60 * 10000000;
                ft1 -= 60 * 10000000;
            }
    */
    //        SYSTEMTIME st2;
    //        FileTimeToSystemTime((FILETIME*)&ft1, &st2);
    WCHAR* cStart;
    if (lpRI->szMemberID[0] == L'\0')
        cStart = lstrstr(szOutBuffer, L"feed-row-wide");
    else
        cStart = lstrstr(szOutBuffer, L"pandect-content-img");
    while (cStart && cStart < szOutBuffer + 1024 * 1024 * 3 - 128)
    {
        GetLocalTime(&st);
        UINT tid = 0;

        WCHAR R = cStart[64];
        cStart[64] = L'\0';
        WCHAR* cGray = NULL;
        cGray = lstrstr(cStart, L"feed-row-grey");
        cStart[64] = R;
        if (cGray != NULL && cGray < cStart + 64)
            SmzdmItem.bGrey = TRUE;
        else
            SmzdmItem.bGrey = FALSE;

        if (SmzdmItem.bGrey == FALSE || lpRI->szMemberID[0] != L'\0' || (bList && bGrey))//不是灰色的继续
        {
            cStart += 12;
            if (lpRI->szMemberID[0] == L'\0')
            {
                WCHAR* cID = lstrstr(cStart, L"article_id");
                if (cID)//////第一个商品ID
                {
                    WCHAR* cIDLeft = lstrstr(cID, L":");
                    if (cIDLeft)
                    {
                        cIDLeft += 2;
                        tid = my_wtoi(cIDLeft);
                        WCHAR wid[10];
                        WCHAR* cIDRight = lstrstr(cIDLeft, L"'");
                        if (cIDRight)
                        {
                            if (cIDRight - cIDLeft < 10)
                                lstrcpyn(wid, cIDLeft,int( cIDRight - cIDLeft + 1));
                        }
                        if (iID == 0)
                            iID = tid;
                        if (wID[0] == L'\0')
                            lstrcpy(wID, wid);
                        //                            if (lstrcmp(wid, lpRI->szID) == 0 && lpRI->szID[0] != L'\0' && !bList)
//                            if ((isPushed(lpRI,tid) || (lstrcmp(wid, lpRI->szID) == 0 && lpRI->szID[0] != L'\0')) && !bList && !bZhi)
//                                break;
                        if (lpRI->bMemberPost && lstrcmp(wid, lpRI->szID) == 0 && lpRI->szID[0] != L'\0')//如果是文章且和上次一样ID则停止搜索
                            break;
                    }
                }
                WCHAR* cLink = lstrstr(cStart, L"href=");
                if (cLink)
                {
                    WCHAR* cLinkLeft = lstrstr(cLink, L"\"");
                    if (cLinkLeft)
                    {
                        cLinkLeft += 1;
                        WCHAR* cLinkRight = lstrstr(cLinkLeft, L"\"");
                        if (cLinkRight)
                        {
                            int n = int(cLinkRight - cLinkLeft + 1);
                            if (n > 63)
                                n = 63;
                            if (cLinkLeft[0] == L'/')
                            {
                                if (n == 63)
                                    n -= 6;
                                lstrcpy(SmzdmItem.szLink, L"https:");
                                lstrcpyn(SmzdmItem.szLink + 6, cLinkLeft, n);
                            }
                            else
                                lstrcpyn(SmzdmItem.szLink, cLinkLeft, n);
                        }
                    }
                }
                WCHAR* cImg = lstrstr(cStart, L"img src");
                if (cImg)
                {
                    WCHAR* cImgLeft = lstrstr(cImg, L"//");
                    if (cImgLeft)
                    {
                        cImgLeft += 2;
                        WCHAR* cImgRight = lstrstr(cImgLeft, L"\"");
                        if (cImgRight)
                        {
                            int n = int(cImgRight - cImgLeft + 1);
                            if (n > 127)
                                n = 127;
                            lstrcpyn(SmzdmItem.szImg, cImgLeft, n);
                        }
                    }
                }
                BOOL bContinue = FALSE;
                WCHAR* cTitle = lstrstr(cStart, L"alt=");
                if (cTitle)
                {
                    WCHAR* cTitleLeft = lstrstr(cTitle, L"\"");
                    if (cTitleLeft)
                    {
                        cTitleLeft += 1;
                        WCHAR* cTitleRight = lstrstr(cTitleLeft, L"\"");
                        if (cTitleRight)
                        {
                            int n = int(cTitleRight - cTitleLeft + 1);
                            if (n > 127)
                                n = 127;
                            lstrcpyn(SmzdmItem.szTitle, cTitleLeft, n);
                        }
                    }
                }
                WCHAR* cTalk = lstrstr(cStart, L"z-icon-talk-o-thin");
                if (cTalk)
                {
                    WCHAR* cTalkLeft = lstrstr(cTalk, L"i>");
                    if (cTalkLeft)
                    {
                        cTalkLeft += 2;
                        SmzdmItem.lTalk = my_wtoi(cTalkLeft);
                    }
                }
                if (!lpRI->bMemberPost)//商品非文章
                {
                    WCHAR* cPrice = lstrstr(cStart, L"z-highlight");
                    if (cPrice)
                    {
                        WCHAR* cPriceLeft = lstrstr(cPrice, L">");
                        if (cPriceLeft)
                        {
                            cPriceLeft += 1;
                            SmzdmItem.fPrice = (float)my_wtof(cPriceLeft);
                        }
                    }

                    WCHAR* cDescripe = lstrstr(cStart, L"feed-block-descripe-top");
                    if (cDescripe)
                    {
                        WCHAR* cDescripeLeft = lstrstr(cDescripe, L">");
                        if (cDescripeLeft)
                        {
                            cDescripeLeft += 1;
                            while (cDescripeLeft[0] == L' ' || cDescripeLeft[0] == L'\r' || cDescripeLeft[0] == L'\n')
                            {
                                cDescripeLeft += 1;
                            }
                            WCHAR* cDescripeRight = lstrstr(cDescripeLeft, L"</div");
                            if (cDescripeRight)
                            {
                                int sCount = int(cDescripeRight - cDescripeLeft + 1);
                                if (sCount >= 512)
                                    sCount = 511;
                                lstrcpyn(SmzdmItem.szDescribe, cDescripeLeft, sCount);
                            }
                        }
                    }

                    WCHAR* cZhi = lstrstr(cStart, L"z-icon-zhi-o-thin");
                    if (cZhi)
                    {
                        WCHAR* cZhiLeft = lstrstr(cZhi, L"span");
                        if (cZhiLeft)
                        {
                            cZhiLeft += 5;
                            SmzdmItem.lZhi = my_wtoi(cZhiLeft);
                        }
                    }

                    WCHAR* cBuZhi = lstrstr(cStart, L"z-icon-buzhi-o-thin");
                    if (cBuZhi)
                    {
                        WCHAR* cBuZhiLeft = lstrstr(cBuZhi, L"span");
                        if (cBuZhiLeft)
                        {
                            cBuZhiLeft += 5;
                            SmzdmItem.lBuZhi = my_wtoi(cBuZhiLeft);
                        }
                    }

                    WCHAR* cStar = lstrstr(cStart, L"z-icon-star-o-thin");
                    if (cStar)
                    {
                        WCHAR* cStarLeft = lstrstr(cStar, L"span>");
                        if (cStarLeft)
                        {
                            cStarLeft += 5;
                            SmzdmItem.lStar = my_wtoi(cStarLeft);
                        }
                    }
                    WCHAR* cGoPath = lstrstr(cStart, L"go_path");
                    if (cGoPath)
                    {
                        WCHAR* cGoPathLeft = lstrstr(cGoPath, L":");
                        if (cGoPathLeft)
                        {
                            cGoPathLeft += 2;
                            WCHAR* cGoPathRight = lstrstr(cGoPathLeft, L"\'");
                            if (cGoPathRight)
                            {
                                int n = int(cGoPathRight - cGoPathLeft + 1);
                                if (n > 509)
                                    n = 509;
                                lstrcpyn(SmzdmItem.szGoPath, cGoPathLeft, n);
                            }
                        }
                    }
                }
                else
                {
                    WCHAR* cZhi = lstrstr(cStart, L"z-icon-thumb-up-o-thin");
                    if (cZhi)
                    {
                        WCHAR* cZhiLeft = lstrstr(cZhi, L"number\">");
                        if (cZhiLeft)
                        {
                            cZhiLeft += 8;
                            SmzdmItem.lZhi = my_wtoi(cZhiLeft);
                        }
                    }
                    WCHAR* cStar = lstrstr(cStart, L"z-icon-star-o-thin");
                    if (cStar)
                    {
                        WCHAR* cStarLeft = lstrstr(cStar, L"span>");
                        if (cStarLeft)
                        {
                            cStarLeft += 5;
                            SmzdmItem.lStar = my_wtoi(cStarLeft);
                        }
                    }
                    WCHAR* cBusiness = lstrstr(cStart, L"z-avatar-name");
                    if (cBusiness)
                    {
                        WCHAR* cBusinessLeft = lstrstr(cBusiness, L">");
                        if (cBusinessLeft)
                        {
                            cBusinessLeft += 1;
                            WCHAR* cBusinessRight = lstrstr(cBusinessLeft, L"</");
                            if (cBusinessRight)
                            {
                                int n = int(cBusinessRight - cBusinessLeft + 1);
                                if (n > 16)
                                    n = 16;
                                lstrcpyn(SmzdmItem.szBusiness, cBusinessLeft, n);
                            }
                        }
                    }
                }
                WCHAR* cTime = lstrstr(cStart, L"feed-block-extras");
                if (cTime)
                {
                    cTime = lstrstr(cTime, L">");
                    if (cTime)
                    {
                        WCHAR* cDateLeft = lstrstr(cTime, L"-");
                        WCHAR* cTimeLeft = lstrstr(cTime, L":");
                        if (cDateLeft && cDateLeft < cTimeLeft)
                        {
                            if (cDateLeft[3] == L'-')
                            {
                                st.wYear = my_wtoi(cDateLeft - 4);
                                cDateLeft += 3;
                                cTimeLeft = NULL;
                                st.wHour = 0;
                                st.wMinute = 0;
                            }
                            WCHAR* cDateRight = cDateLeft + 1;
                            cDateLeft -= 2;
                            st.wMonth = my_wtoi(cDateLeft);
                            st.wDay = my_wtoi(cDateRight);
                        }
                        if (cTimeLeft)
                        {
                            WCHAR* cTimeRight = cTimeLeft + 1;
                            cTimeLeft -= 2;
                            st.wHour = my_wtoi(cTimeLeft);
                            st.wMinute = my_wtoi(cTimeRight);
                            /*
                                            while (cTimeRight[0] != L' ')
                                            {
                                                cTimeRight += 1;
                                            }
                                            lstrcpyn(szTime, cTimeLeft, cTimeRight - cTimeLeft+1);
                            */
                        }
                        SystemTimeToFileTime(&st, (FILETIME*)&ft2);
                        if (ft1 > ft2 && !bList && !bZhi && !lpRI->bScore)
                        {
                            break;
                            /*
                                                            //								if (lpRI->szID[0] != L'\0')
                                                            if (lpRI->uid != 0 || lpRI->szID[0] != L'\0')
                                                                break;
                                                            else
                                                            {
                                                                if (iID != 0)
                                                                    lpRI->uid = iID;
                                                                if (wID[0] != L'\0')
                                                                    lstrcpy(lpRI->szID, wID);
                                                            }
                            */
                        }
                        //                            if (lpRI->uid == 0)
                        //                                lpRI->uid = iID;
                        if (!lpRI->bMemberPost)
                        {
                            WCHAR* cBusiness = lstrstr(cTime, L"<span");
                            if (cBusiness)
                            {
                                WCHAR* cBusinessLeft = lstrstr(cBusiness, L">");
                                if (cBusinessLeft)
                                {
                                    cBusinessLeft += 1;
                                    while (cBusinessLeft[0] == L' ' || cBusinessLeft[0] == L'\r' || cBusinessLeft[0] == L'\n')
                                    {
                                        cBusinessLeft += 1;
                                    }
                                    WCHAR* cBusinessRight = cBusinessLeft;
                                    while (cBusinessRight[0] != L' ')
                                    {
                                        cBusinessRight += 1;
                                    }
                                    int n = int(cBusinessRight - cBusinessLeft + 1);
                                    if (n > 16)
                                        n = 16;
                                    lstrcpyn(SmzdmItem.szBusiness, cBusinessLeft, n);
                                }
                            }
                        }
                    }
                }
                if (lstrlen(lpRI->szFilter) != 0)//过滤词
                {
                    WCHAR* cFilterLeft = lpRI->szFilter;
                    while (cFilterLeft)
                    {
                        WCHAR* cFilterRight = lstrstr(cFilterLeft, L" ");
                        if (cFilterRight)
                            cFilterRight[0] = L'\0';
                        if (lstrstr(SmzdmItem.szTitle, cFilterLeft) || lstrstr(SmzdmItem.szDescribe, cFilterLeft))
                        {
                            if (cFilterRight)
                                cFilterRight[0] = L' ';
                            bContinue = TRUE;
                            break;
                        }
                        if (cFilterRight)
                        {
                            cFilterRight[0] = L' ';
                            cFilterLeft = cFilterRight + 1;
                            while (cFilterLeft[0] == L' ')
                            {
                                cFilterLeft++;
                            }
                        }
                        else
                            cFilterLeft = 0;
                    }
                }
                if (bContinue)
                {
                    cStart = lstrstr(cStart, L"feed-row-wide");
                    continue;
                }
            }
            else///////////////////////////////////////////////////////////////按值友ID搜索
            {
                BOOL bContinue = FALSE;
                WCHAR* cImg = lstrstr(cStart, L"src=");
                if (cImg)
                {
                    WCHAR* cImgLeft = lstrstr(cImg, L"//");
                    if (cImgLeft)
                    {
                        cImgLeft += 2;
                        WCHAR* cImgRight = lstrstr(cImgLeft, L"\"");
                        if (cImgRight)
                        {
                            int n = int(cImgRight - cImgLeft + 1);
                            if (n > 127)
                                n = 127;
                            lstrcpyn(SmzdmItem.szImg, cImgLeft, n);
                        }
                    }
                }
                WCHAR* cLink = lstrstr(cStart, L"href=");
                if (cLink)
                {
                    WCHAR* cLinkLeft = lstrstr(cLink, L"\"");
                    if (cLinkLeft)
                    {
                        cLinkLeft += 1;
                        WCHAR* cLinkRight = lstrstr(cLinkLeft, L"\"");
                        if (cLinkRight)
                        {
                            int n = int(cLinkRight - cLinkLeft + 1);
                            if (n > 63)
                                n = 63;
                            if (cLinkLeft[0] == L'/')
                            {
                                if (n == 63)
                                    n -= 6;
                                lstrcpy(SmzdmItem.szLink, L"https:");
                                lstrcpyn(SmzdmItem.szLink + 6, cLinkLeft, n);
                            }
                            else
                                lstrcpyn(SmzdmItem.szLink, cLinkLeft, n);

                        }
                    }
                    WCHAR* cUid = lstrstr(cLink, L"/p/");
                    if (cUid)
                    {
                        cUid += 3;

                        WCHAR wid[10];
                        WCHAR* cUidRight = lstrstr(cUid, L"/");
                        if (!lpRI->bMemberPost)
                        {
                            tid = my_wtoi(cUid);
                            if (iID == 0)
                                iID = tid;
                        }
                        else if (cUidRight < cUid + 10)
                        {
                            lstrcpyn(wid, cUid, int(cUidRight - cUid + 1));
                            if (wID[0] == L'\0')
                                lstrcpy(wID, wid);
                            if (lstrcmp(wid, lpRI->szID) == 0 && !bList)
                                break;
                        }
                    }
                    if (lpRI->bMemberPost)
                    {
                        WCHAR* cTitle = lstrstr(cStart, L"pandect-content-title");
                        if (cTitle)
                        {
                            WCHAR* cTitleLeft = lstrstr(cTitle, L"blank\">");
                            if (cTitleLeft)
                            {
                                cTitleLeft += 7;
                                WCHAR* cTitleRight = lstrstr(cTitleLeft, L"</a");
                                if (cTitleRight)
                                {
                                    int n = int(cTitleRight - cTitleLeft + 1);
                                    if (n > 127)
                                        n = 127;
                                    lstrcpyn(SmzdmItem.szTitle, cTitleLeft, n);
                                }
                            }
                        }
                        WCHAR* cDescripe = lstrstr(cStart, L"pandect-content-detail");
                        if (cDescripe)
                        {
                            WCHAR* cDescripeLeft = lstrstr(cDescripe, L">");
                            if (cDescripeLeft)
                            {
                                cDescripeLeft += 1;
                                WCHAR* cDescripeRight = lstrstr(cDescripeLeft, L"</d");
                                if (cDescripeRight)
                                {
                                    int n = int(cDescripeRight - cDescripeLeft + 1);
                                    if (n > 511)
                                        n = 511;
                                    lstrcpyn(SmzdmItem.szDescribe, cDescripeLeft, n);
                                }
                            }
                        }
                    }
                    else
                    {
                        WCHAR* cTitle1 = lstrstr(cLink, L"</i>");
                        WCHAR* cTitle2 = lstrstr(cLink, L"</a>");
                        WCHAR* cTitle;
                        if (cTitle2 > cTitle1)
                            cTitle = cTitle1 + 2;
                        else
                            cTitle = lstrstr(cLink, L"\">");
                        if (cTitle)
                        {
                            cTitle += 2;
                            while (cTitle[0] == L' ' || cTitle[0] == L'\r' || cTitle[0] == L'\n')
                            {
                                cTitle += 1;
                            }
                            WCHAR* cTitleRight = lstrstr(cTitle, L"</");
                            if (cTitleRight)
                            {
                                int n = int(cTitleRight - cTitle + 1);
                                if (n > 127)
                                    n = 127;
                                lstrcpyn(SmzdmItem.szTitle, cTitle, n);
                            }
                            WCHAR* cPrice = lstrstr(cTitle, L"元");
                            if (cPrice)
                            {
                                cPrice -= 1;
                                while ((cPrice[0] >= L'0' && cPrice[0] <= L'9') || cPrice[0] == L'.')
                                {
                                    cPrice -= 1;
                                }
                                cPrice += 1;
                                SmzdmItem.fPrice = (float)my_wtof(cPrice);
                                if ((SmzdmItem.fPrice > lpRI->uMaxPrice && lpRI->uMaxPrice != 0) || (SmzdmItem.fPrice < lpRI->uMinPrice && lpRI->uMinPrice != 0))
                                    bContinue = TRUE;
                            }
                        }
                    }
                }
                if (lstrlen(lpRI->szKey) != 0)
                {
                    bContinue = TRUE;
                    WCHAR* cKeyLeft = lpRI->szKey;
                    while (cKeyLeft)
                    {
                        WCHAR* cKeyRight = lstrstr(cKeyLeft, L" ");
                        if (cKeyRight)
                            cKeyRight[0] = L'\0';
                        if (lstrstr(SmzdmItem.szTitle, cKeyLeft))
                        {
                            if (cKeyRight)
                                cKeyRight[0] = L' ';
                            bContinue = FALSE;
                            break;
                        }
                        if (cKeyRight)
                        {
                            cKeyRight[0] = L' ';
                            cKeyLeft = cKeyRight + 1;
                            while (cKeyLeft[0] == L' ')
                            {
                                cKeyLeft++;
                            }
                        }
                        else
                            cKeyLeft = 0;
                    }
                }
                if (lstrlen(lpRI->szFilter) != 0)
                {
                    WCHAR* cFilterLeft = lpRI->szFilter;
                    while (cFilterLeft)
                    {
                        WCHAR* cFilterRight = lstrstr(cFilterLeft, L" ");
                        if (cFilterRight)
                            cFilterRight[0] = L'\0';
                        if (lstrstr(SmzdmItem.szTitle, cFilterLeft))
                        {
                            if (cFilterRight)
                                cFilterRight[0] = L' ';
                            bContinue = TRUE;
                            break;
                        }
                        if (cFilterRight)
                        {
                            cFilterRight[0] = L' ';
                            cFilterLeft = cFilterRight + 1;
                            while (cFilterLeft[0] == L' ')
                            {
                                cFilterLeft++;
                            }
                        }
                        else
                            cFilterLeft = 0;
                    }
                }
                if (bContinue)
                {
                    cStart = lstrstr(cStart, L"pandect-content-img");
                    continue;
                }
                WCHAR* cTime = lstrstr(cStart, L"pandect-content-time");
                if (cTime)
                {
                    cTime = lstrstr(cTime, L">");
                    if (cTime)
                    {
                        cTime += 1;
                        WCHAR* cTimeHour = lstrstr(cTime, L"小时");
                        WCHAR* cTimeMin = lstrstr(cTime, L"分钟");
                        if (cTimeHour || cTimeMin)
                        {
                            GetLocalTime(&st);
                            ULONGLONG ft1, ft2;
                            SystemTimeToFileTime(&st, (LPFILETIME)&ft1);
                            if (cTimeMin)
                            {
                                cTimeMin -= 1;
                                while ((cTimeMin[0] >= L'0' && cTimeMin[0] <= L'9'))cTimeMin -= 1;
                                cTimeMin += 1;
                                ft2 = my_wtoi(cTimeMin);
                                ft1 -= ft2 * 60 * 10000000;
                            }
                            else if (cTimeHour)
                            {
                                cTimeHour -= 1;
                                while ((cTimeHour[0] >= L'0' && cTimeHour[0] <= L'9'))cTimeHour -= 1;
                                cTimeHour += 1;
                                int n = my_wtoi(cTimeHour);
                                for (int i = 0; i < n; i++)
                                {
                                    ft1 -= 36000000000;
                                }
                            }
                            FileTimeToSystemTime((FILETIME*)&ft1, &st);
                        }
                        else
                        {

                            WCHAR* cDateLeft = lstrstr(cTime, L"-");
                            WCHAR* cTimeLeft = lstrstr(cTime, L":");
                            if (cDateLeft && cDateLeft < cTimeLeft)
                            {
                                if (cDateLeft[3] == L'-')
                                {
                                    st.wYear = my_wtoi(cDateLeft - 4);
                                    cDateLeft += 3;
                                    cTimeLeft = NULL;
                                    st.wHour = 0;
                                    st.wMinute = 0;
                                }
                                WCHAR* cDateRight = cDateLeft + 1;
                                cDateLeft -= 2;
                                st.wMonth = my_wtoi(cDateLeft);
                                st.wDay = my_wtoi(cDateRight);
                            }
                            if (cTimeLeft)
                            {
                                WCHAR* cTimeRight = cTimeLeft + 1;
                                cTimeLeft -= 2;
                                st.wHour = my_wtoi(cTimeLeft);
                                st.wMinute = my_wtoi(cTimeRight);
                            }
                        }
                        SystemTimeToFileTime(&st, (FILETIME*)&ft2);
                        if (ft1 > ft2 && !bList)
                            break;
                    }
                }
                //                    if(lpRI->bMemberPost)
                //                        GetMemberZhiStarTalk(szLink, &lZhi, &lBuZhi, &lStar, &lTalk);
            }
            BOOL bYes = TRUE;
            if (bZhi)
            {
                UINT uPercentage;
                if (SmzdmItem.lZhi == 0 || SmzdmItem.lBuZhi > SmzdmItem.lZhi)
                    uPercentage = 0;
                else if (SmzdmItem.lBuZhi == 0)
                    uPercentage = 100;
                else
                    uPercentage = SmzdmItem.lZhi * 100 / (SmzdmItem.lZhi + SmzdmItem.lBuZhi);
                if ((lpRI->uZhi < SmzdmItem.lZhi || lpRI->uZhi == 0) && (lpRI->uBuZhi > SmzdmItem.lBuZhi || lpRI->uBuZhi == 0) && (lpRI->uPercentage <= uPercentage || lpRI->uPercentage == 0) && (SmzdmItem.lTalk > lpRI->uTalk || lpRI->uTalk == 0))
                    bYes = TRUE;
                else
                    bYes = FALSE;
            }
            if (bYes)
            {
                SmzdmItem.st = st;
                if (lpRI->bMemberPost)
                    lstrcpy(SmzdmItem.szGoPath, SmzdmItem.szLink);
                if (bList)
                {
                    WriteItem(TRUE, &SmzdmItem);
                    WCHAR sz[64];
                    LVITEM li = { 0 };
                    int iSub = 0;
                    li.mask = LVIF_TEXT;
                    li.pszText = SmzdmItem.szTitle;
                    li.iSubItem = iSub++;
                    li.iItem = ListView_GetItemCount(hList);
                    li.iItem = ListView_InsertItem(hList, &li);
                    li.pszText = SmzdmItem.szDescribe;
                    li.iSubItem = iSub++;
                    //                    ListView_SetItem(hList, &li);
                    int p = int(SmzdmItem.fPrice * 100);
                    wsprintf(sz, L"%d.%2.2d", p / 100, p % 100);
                    li.pszText = sz;
                    li.iSubItem = iSub++;
                    ListView_SetItem(hList, &li);
                    li.pszText = SmzdmItem.szImg;
                    li.iSubItem = iSub++;
                    ListView_SetItem(hList, &li);
                    wsprintf(sz, L"%d", SmzdmItem.lZhi);
                    li.pszText = sz;
                    li.iSubItem = iSub++;
                    ListView_SetItem(hList, &li);
                    wsprintf(sz, L"%d", SmzdmItem.lBuZhi);
                    li.pszText = sz;
                    li.iSubItem = iSub++;
                    ListView_SetItem(hList, &li);
                    wsprintf(sz, L"%d", SmzdmItem.lStar);
                    li.pszText = sz;
                    li.iSubItem = iSub++;
                    ListView_SetItem(hList, &li);
                    wsprintf(sz, L"%d", SmzdmItem.lTalk);
                    li.pszText = sz;
                    li.iSubItem = iSub++;
                    ListView_SetItem(hList, &li);
                    wsprintf(sz, L"%d-%2.2d-%2.2d %2.2d:%2.2d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
                    li.pszText = sz;
                    li.iSubItem = iSub++;
                    ListView_SetItem(hList, &li);
                    li.pszText = SmzdmItem.szBusiness;
                    li.iSubItem = iSub++;
                    ListView_SetItem(hList, &li);
                    li.pszText = SmzdmItem.szLink;
                    li.iSubItem = iSub++;
                    ListView_SetItem(hList, &li);
                    li.pszText = SmzdmItem.szGoPath;
                    li.iSubItem = iSub++;
                    ListView_SetItem(hList, &li);

                    //                    WCHAR szToken[] = L"SCT152372TQlJTExCGuU63HYmj8Uargtjb";
                    //                    SendServerJ(szToken, szTitle, szDescripe, szLink, fPrice, szBusiness, szImg);

                }
                else
                {
                    BOOL bYes = TRUE;
                    if (!lpRI->bMemberPost)
                    {
                        if (isPushed(lpRI, tid))
                            bYes = FALSE;
                        else
                            SetOldPushed(lpRI, tid);
                    }
                    if (bYes)
                    {
                        WCHAR wTitle[192], wDescripe[666];
                        int p = int(SmzdmItem.fPrice * 100);
                        if (lpRI->szMemberID[0] == L'\0')
                        {
                            if (p == 0)
                                wsprintf(wTitle, L"%s %s", SmzdmItem.szTitle, SmzdmItem.szBusiness);
                            else
                                wsprintf(wTitle, L"%d.%2.2d元 %s %s", p / 100, p % 100, SmzdmItem.szTitle, SmzdmItem.szBusiness);
                        }
                        else
                        {
                            if (lpRI->bMemberPost)
                                lstrcpy(wTitle, SmzdmItem.szTitle);
                            else
                            {
                                int p = int(SmzdmItem.fPrice * 100);
                                wsprintf(wTitle, L"%d.%2.2d元 %s", p / 100, p % 100, SmzdmItem.szTitle);
                            }
                        }
                        if (lpRI->szKey[0] != L'\0')
                            wsprintf(wDescripe, L"~%s~ %s", lpRI->szKey, SmzdmItem.szDescribe);
                        else
                            wsprintf(wDescripe, L"~%s~ %s", lpRI->szMember, SmzdmItem.szDescribe);
                        lstrcpyn(SmzdmItem.szDescribe, wDescripe, 512);
                        WriteItem(FALSE, &SmzdmItem);
                        if ((RemindSave.bTips && lpRI->iSend == 0) || lpRI->iSend == 2)
                        {
                            if (bNewTrayTips)
                            {
                                CreateDirectory(L"cache", NULL);
                                WCHAR wImg[MAX_PATH];
                                GetCurrentDirectory(MAX_PATH, wImg);
                                lstrcat(wImg, L"\\cache\\");
                                WCHAR* wFileLeft = lstrstr(SmzdmItem.szImg + 2, L"/");;
                                while (true)
                                {
                                    wFileLeft += 1;
                                    WCHAR* wFileRight = lstrstr(wFileLeft, L"/");
                                    if (!wFileRight)
                                        break;
                                    else
                                        wFileLeft = wFileRight;
                                }
                                lstrcat(wImg, wFileLeft);
                                winhttpDownload(SmzdmItem.szImg, wImg);
                                ShowToast(wTitle, wDescripe, wImg, SmzdmItem.szLink);
                            }
                            else
                            {

                                nid.uFlags = NIF_MESSAGE | NIF_INFO | NIF_TIP | NIF_ICON;
                                //                            nid.dwState = NIS_SHAREDICON;
                                //                            nid.dwStateMask = NIS_SHAREDICON;
                                //							nid.uVersion = NOTIFYICON_VERSION_4;
                                //							nid.hBalloonIcon = iMain;
                                nid.dwInfoFlags = NIIF_NONE;
                                //                            nid.uID = tid;
                                nid.uTimeout = tid;
                                lstrcpyn(nid.szInfoTitle, wTitle, 63);
                                lstrcpyn(nid.szInfo, wDescripe, 255);
                                Shell_NotifyIcon(NIM_MODIFY, &nid);
                                //                            Shell_NotifyIcon(NIM_SETVERSION, &nid);
                            }
                        }
                        if ((RemindSave.bBark && lpRI->iSend == 0) || lpRI->iSend == 5)
                        {
                            SendBark(RemindSave.szBarkUrl, RemindSave.szBarkSound, wTitle, wDescripe, SmzdmItem.szLink, SmzdmItem.szImg);
                        }
                        if ((RemindSave.bDingDing && lpRI->iSend == 0) || lpRI->iSend == 4)
                        {
                            SendDingDing(RemindSave.szDingDingToken, wTitle, wDescripe, SmzdmItem.szLink, SmzdmItem.szImg);
                        }
                        if ((RemindSave.bWeChat && lpRI->iSend == 0) || lpRI->iSend == 3)
                        {
                            SendWeChatPusher(RemindSave.szWeChatUserID, wTitle, wDescripe, SmzdmItem.szLink, SmzdmItem.szImg);
                        }
                        if ((RemindSave.bWxPusher && lpRI->iSend == 0) || lpRI->iSend == 6)
                        {
                            SendWxPusher(RemindSave.szWxPusherUID, wTitle, wDescripe, SmzdmItem.szLink, SmzdmItem.szImg);
                        }
                        if ((RemindSave.bDirectly && lpRI->iSend == 0) || lpRI->iSend == 1)
                            ShellExecute(NULL, L"open", SmzdmItem.szLink, NULL, NULL, SW_SHOWNOACTIVATE);
                    }
                }
            }
        }
        else
            cStart += 2;
        if (lpRI->szMemberID[0] == L'\0')
            cStart = lstrstr(cStart, L"feed-row-wide");
        else
            cStart = lstrstr(cStart, L"pandect-content-img");
    }
    if (bList)
        SendMessage(hList, WM_SETREDRAW, TRUE, FALSE);
    //        if (iID != 0)
    //            lpRI->uid = iID;
    if (wID[0] != L'\0' && iPage == 0)
        lstrcpy(lpRI->szID, wID);
    delete[] szOutBuffer;
    return TRUE;
}
int iReset = 11;
#ifndef _DEBUG
extern "C" void WinMainCRTStartup()
{
#else
int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);
#endif
#ifdef NDEBUG
	if (OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, szAppName) == NULL)/////////////////////////创建守护进程
	{
		HANDLE hMap = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(REMINDDATA), szAppName);
		if (hMap)
		{
			lpRemindData = (REMINDDATA*)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(REMINDDATA));
			ZeroMemory(lpRemindData, sizeof(REMINDDATA));
			while (lpRemindData->bExit == FALSE&&iReset!=0)
			{
				HANDLE hProcess;
				RunProcess(0, 0, &hProcess);
                EmptyProcessMemory(NULL);;
				WaitForSingleObject(hProcess, INFINITE);
				CloseHandle(hProcess);
                iReset--;
                if (lpRemindData->bExit == FALSE&&iReset!=0)
                    Sleep(6666);                
			}
			UnmapViewOfFile(lpRemindData);
			CloseHandle(hMap);
			ExitProcess(0);
			return;
		}
	}
#endif
	hMap = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, szAppName);
	if (hMap)
	{
        lpRemindData = (REMINDDATA*)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(REMINDDATA));
	}
#ifdef NDEBUG
#else
	else
	{
		hMap = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(BOOL), szAppName);
        lpRemindData = (REMINDDATA*)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(REMINDDATA));
		ZeroMemory(lpRemindData, sizeof(REMINDDATA));
	}
#endif // !DAEMON
	typedef WINUSERAPI DWORD WINAPI RTLGETVERSION(PRTL_OSVERSIONINFOW  lpVersionInformation);
	rovi.dwOSVersionInfoSize = sizeof(rovi);
	RTLGETVERSION* RtlGetVersion = (RTLGETVERSION*)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
	if (RtlGetVersion)
		RtlGetVersion(&rovi);
	hMutex = CreateMutex(NULL, TRUE, L"_SmzdmRemind_");
    if (hMutex != NULL)
    {
        if (ERROR_ALREADY_EXISTS != GetLastError())
        {
/*
            INITCOMMONCONTROLSEX icce;
            icce.dwSize = sizeof INITCOMMONCONTROLSEX;
            icce.dwICC = ICC_LISTVIEW_CLASSES;
            InitCommonControlsEx(&icce);
*/
            hInst = GetModuleHandle(NULL);
            // 执行应用程序初始化:
            if (!InitInstance(hInst, SW_SHOW))
            {
#if NDEBUG
                return;
#else
                return 0;
#endif
            }


            MSG msg;

            // 主消息循环:
            while (GetMessage(&msg, nullptr, 0, 0))
            {
                if (!IsDialogMessage(hMain, &msg))
                {
                    TranslateMessage(&msg);
                    DispatchMessage(&msg);
                }
            }
            bExit = TRUE;
            CloseHandle(hGetDataThread);
            Shell_NotifyIcon(NIM_DELETE, &nid);
            DestroyIcon(iMain);
//            DestroyIcon(iTray);
            CloseHandle(hMap);
            hMap = NULL;
			if (hMutex)
				CloseHandle(hMutex);
//            return (int)msg.wParam;
        }
        else
        {
            LoadString(hInst, IDS_TIPS, nid.szTip, 88);
            HWND hWnd = FindWindow(NULL, nid.szTip);
            if (hWnd)
            {
                ShowWindow(hWnd, SW_SHOW);
                SetForeground(hWnd);
            }
        }
    }
	if (hMap)
		CloseHandle(hMap);
    ExitProcess(0);
}
DWORD WINAPI GetDataThreadProc(PVOID pParam)//获取网站数据线程
{
    int iSign = 36;
	while (!bExit)
	{
		DWORD dStart = GetTickCount();
        if (!bOpen)
        {
            dStart -= iTimes[RemindSave.iTime] * 60000;
            dStart += 8888;
        }
		while (true)
		{
			DWORD dTime = GetTickCount() - dStart;
			if (dTime > iTimes[RemindSave.iTime] * 60000)
				break;
			else
				Sleep(988);
            WCHAR sz[16];
            wsprintf(sz, L"%d秒后获取", (iTimes[RemindSave.iTime] * 60000 - dTime) / 1000);
            SetDlgItemText(hMain, IDC_STATIC_COUNTDOWN, sz);
			if (bResetTime)
			{
                dStart = GetTickCount();
				dStart -= iTimes[RemindSave.iTime] * 60000;
				dStart += 8888;
				bResetTime = FALSE;
			}
		}
        bGetData = TRUE;
        WCHAR tips[] = L"正在从网站获取并处理数据请稍后...";
		int n = riSize / sizeof REMINDITEM;
		for (int i = 0; i < n; i++)
		{
            if (!lpRemindItem[i].bNotUse)
            {
                WCHAR wTips[256];
                lstrcpy(wTips, tips);
                if(lstrlen(lpRemindItem[i].szKey))
                    lstrcat(wTips, lpRemindItem[i].szKey);
                else
                    lstrcat(wTips, lpRemindItem[i].szMember);
                SetWindowText(hMain, wTips);
                SearchSMZDM(&lpRemindItem[i], FALSE, FALSE, FALSE,FALSE);
                if(!lpRemindItem[i].bMemberPost&&lpRemindItem[i].szMemberID[0]!=L'\0')
                    SearchSMZDM(&lpRemindItem[i], FALSE, 2, FALSE,FALSE);
            }
		}
		WriteSet(NULL);
        if (iSign == 36)
        {
            SendMessage(hMain, WM_COMMAND, IDC_SIGN_IN1, 1);
            SendMessage(hMain, WM_COMMAND, IDC_SIGN_IN2, 1);

            WCHAR wCookie[CookieSize];
            ReadCookieFromFile(2, wCookie);
            if (wCookie[0] != L'\0')
            {
                SetWindowText(hMain, L"正在签到---卡饭论坛...");
                SignKaFan(wCookie);
            }
            ReadCookieFromFile(3, wCookie);
            if (wCookie[0] != L'\0')
            {
                SetWindowText(hMain, L"正在签到---数码之家...");
                SignMyDigit(wCookie);
            }
            ReadCookieFromFile(4, wCookie);
            if (wCookie[0] != L'\0')
            {
                SetWindowText(hMain, L"正在签到---远景论坛...");
                SignPCBeta(wCookie);
            }
            ReadCookieFromFile(5, wCookie);
            if (wCookie[0] != L'\0')
            {
                SetWindowText(hMain, L"正在签到---V2EX...");
                SignV2EX(wCookie);
            }
            ReadCookieFromFile(6, wCookie);
            if (wCookie[0] != L'\0')
            {
                SetWindowText(hMain, L"正在签到---98堂...");
                SignSeHuaTang(wCookie);
            }
            ReadCookieFromFile(7, wCookie);
            if (wCookie[0] != L'\0')
            {
                SetWindowText(hMain, L"正在签到---百度贴吧...");
                SignTieba(wCookie);
            }
            iSign = 0;
        }
        iSign++;
		SetWindowText(hMain, nid.szTip);
        bOpen = TRUE;
        bGetData = FALSE;
	}
	return TRUE;
}
//
//   函数: InitInstance(HINSTANCE, int)
//
//   目标: 保存实例句柄并创建主窗口
//
//   注释:
//
//        在此函数中，我们在全局变量中保存实例句柄并
//        创建和显示主程序窗口。
//
BOOL bInit = TRUE;
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
    hInst = hInstance; // 将实例句柄存储在全局变量中    
    hMain = ::CreateDialog(hInst, MAKEINTRESOURCE(IDD_MAIN), NULL, (DLGPROC)MainProc);
    if (!hMain)
    {
        return FALSE;
    }
    iMain = LoadIcon(hInst, MAKEINTRESOURCE(IDI_SMZDMREMIND));
//    iTray = LoadIcon(hInst, MAKEINTRESOURCE(IDI_TRAY));
    SetClassLongPtr(hMain, -14, (LONG_PTR)iMain);
    SetClassLongPtr(hMain, -34, (LONG_PTR)iMain);
    //////////////////////////////////////////////////////////////////////////////////设置通知栏图标
    nid.cbSize = sizeof NOTIFYICONDATA;
    nid.uID = WM_IAWENTRAY;
    nid.hWnd = hMain;
    nid.hIcon = iMain;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_IAWENTRAY;    
    LoadString(hInst, IDS_TIPS, nid.szTip, 88);
    Shell_NotifyIcon(NIM_ADD, &nid);    
    Shell_NotifyIcon(NIM_SETVERSION, &nid);
	hList = GetDlgItem(hMain, IDC_LIST);
    hListRemind = GetDlgItem(hMain, IDC_LIST_REMIND);
    ListView_SetExtendedListViewStyle(hList, LVS_EX_FULLROWSELECT |LVS_EX_GRIDLINES|LVS_EX_INFOTIP);
    ListView_SetExtendedListViewStyle(hListRemind, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES|LVS_EX_CHECKBOXES);
	LVCOLUMN lc;
	lc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM | LVCF_FMT;
	WCHAR szTitle[][6] = { L"标题" ,L"描述" ,L"价格",L"图片",L"值/赞",L"不值",L"收藏",L"评论",L"时间",L"平台/作者",L"链接",L"直达"};
	int iTitle[] = { 505,0,66,0,45,45,45,45,123,138,238,68 };
	for (int i = 0; i < 12; i++)
	{
		lc.cx = iTitle[i];
        if(i==2|| i == 4 || i == 5 || i == 6 || i == 7)
    		lc.fmt = LVCFMT_RIGHT;
        else if(i==1 || i == 3 || i == 10 || i == 11)
            lc.fmt = LVCFMT_LEFT;
        else
            lc.fmt = LVCFMT_CENTER;
		lc.pszText = szTitle[i];
		lc.iSubItem = i;
		ListView_InsertColumn(hList, i, &lc);
	}
    WCHAR szKey[][8] = { L"关键词",L"过滤词",L"最小价格",L"最大价格",L"平台/值友ID"};
    int iKey[] = { 146,100,60,60,88};
    for (int i=0;i<5;i++)
    {
        lc.cx = iKey[i];
        lc.fmt = LVCFMT_CENTER;
        lc.pszText = szKey[i];
        lc.iSubItem = i;
        ListView_InsertColumn(hListRemind, i, &lc);
    }
    hCombo = GetDlgItem(hMain, IDC_COMBO);
    for (int i=0;i<24;i++)
    {
        SendMessage(hCombo, CB_ADDSTRING, NULL, (LPARAM)szBus[i]);
    }
    SendMessage(hCombo, CB_SETCURSEL, 0, 0);
    hComboTime = GetDlgItem(hMain, IDC_COMBO_TIME);
    for (int i=0;i<6;i++)
    {
        SendMessage(hComboTime, CB_ADDSTRING, NULL, (LPARAM)szTimes[i]);
    }
    hComboPage = GetDlgItem(hMain, IDC_COMBO_PAGE);
	for (int i = 0; i < 9; i++)
	{
		SendMessage(hComboPage, CB_ADDSTRING, NULL, (LPARAM)szPage[i]);
	}
	hComboSound = GetDlgItem(hMain, IDC_COMBO_SOUND);
	for (int i = 0; i < 32; i++)
	{
		SendMessage(hComboSound, CB_ADDSTRING, NULL, (LPARAM)szBarkSound[i]);
	}
	hComboSendMode = GetDlgItem(hMain, IDC_COMBO_SEND);
    for (int i = 0; i < 7; i++)
    {
        SendMessage(hComboSendMode, CB_ADDSTRING, NULL, (LPARAM)szSendMode[i]);
    }
    SendMessage(hComboSendMode, CB_SETCURSEL, 0, 0);
	hComBoPercentage = GetDlgItem(hMain, IDC_COMBO_PERCENTAGE);
	for (int i = 0; i < 6; i++)
	{
		SendMessage(hComBoPercentage, CB_ADDSTRING, NULL, (LPARAM)szPercentage[i]);
	}
	SendMessage(hComBoPercentage, CB_SETCURSEL, 0, 0);
	hComboSearch = GetDlgItem(hMain, IDC_COMBO_SEARCH);
	for (int i = 0; i < 3; i++)
	{
		SendMessage(hComboSearch, CB_ADDSTRING, NULL, (LPARAM)szSearch[i]);
	}
	SendMessage(hComboSearch, CB_SETCURSEL, 1, 0);
    ReadSet();
    SendMessage(hComboTime, CB_SETCURSEL, RemindSave.iTime, NULL);
    SendMessage(hComboPage, CB_SETCURSEL, RemindSave.iPage, NULL);
    CheckDlgButton(hMain, IDC_CHECK_OPEN_LINK, RemindSave.bDirectly);
    CheckDlgButton(hMain, IDC_CHECK_WXPUSHER, RemindSave.bWxPusher);
    CheckDlgButton(hMain, IDC_CHECK_TIPS, RemindSave.bTips);
    SetDlgItemText(hMain,IDC_UID, RemindSave.szWxPusherUID);
    CheckDlgButton(hMain, IDC_CHECK_WECHAT, RemindSave.bWeChat);
    SetDlgItemText(hMain, IDC_WECHAT_AID, RemindSave.szWeChatAgentId);
    SetDlgItemText(hMain, IDC_WECHAT_CORPID, RemindSave.szWeChatID);
    SetDlgItemText(hMain, IDC_WECHAT_SECRET,RemindSave.szWeChatSecret);
    SetDlgItemText(hMain, IDC_WECHAT_UID, RemindSave.szWeChatUserID);
    CheckDlgButton(hMain, IDC_CHECK_DINGDING, RemindSave.bDingDing);
    SetDlgItemText(hMain, IDC_ACCESS_TOKEN, RemindSave.szDingDingToken);
    CheckDlgButton(hMain, IDC_CHECK_BARK, RemindSave.bBark);
    SetDlgItemText(hMain, IDC_BARK_URL, RemindSave.szBarkUrl);
    SetDlgItemText(hMain, IDC_COMBO_SOUND, RemindSave.szBarkSound);
    CheckDlgButton(hMain, IDC_CHECK_SCORE, RemindSave.bScoreSort);
    CheckDlgButton(hMain, IDC_CHECK_AUTORUN, AutoRun(FALSE, FALSE, szAppName));
    CheckDlgButton(hMain, IDC_CHECK_GREY, TRUE);
    WCHAR wCookie[CookieSize];
    ReadCookieFromFile(0,wCookie);
    SetDlgItemText(hMain, IDC_COOKIE1, wCookie);
	ReadCookieFromFile(1,wCookie);
	SetDlgItemText(hMain, IDC_COOKIE2, wCookie);
	ReadCookieFromFile(2, wCookie);
	SetDlgItemText(hMain, IDC_EDIT1, wCookie);
	ReadCookieFromFile(3, wCookie);
	SetDlgItemText(hMain, IDC_EDIT2, wCookie);
	ReadCookieFromFile(4, wCookie);
	SetDlgItemText(hMain, IDC_EDIT3, wCookie);
	ReadCookieFromFile(5, wCookie);
	SetDlgItemText(hMain, IDC_EDIT4, wCookie);
	ReadCookieFromFile(6, wCookie);
	SetDlgItemText(hMain, IDC_EDIT5, wCookie);
	ReadCookieFromFile(7, wCookie);
	SetDlgItemText(hMain, IDC_EDIT6, wCookie);
    SendDlgItemMessage(hMain, IDC_EDIT1, EM_SETSEL, 0, -1);
    SendDlgItemMessage(hMain, IDC_EDIT2, EM_SETSEL, 0, -1);
    SendDlgItemMessage(hMain, IDC_EDIT3, EM_SETSEL, 0, -1);
    SendDlgItemMessage(hMain, IDC_EDIT4, EM_SETSEL, 0, -1);
    SendDlgItemMessage(hMain, IDC_EDIT5, EM_SETSEL, 0, -1);
    SendDlgItemMessage(hMain, IDC_EDIT6, EM_SETSEL, 0, -1);
    if (riSize)
    {
		//	ListView_DeleteAllItems(hListRemind);
		int n = riSize / sizeof REMINDITEM;
		for (int i = 0; i < n; i++)
		{
			WCHAR sz[128];
			LVITEM li = { 0 };
			int iSub = 0;
			li.mask = LVIF_TEXT;
			li.pszText = lpRemindItem[i].szKey;
			li.iSubItem = iSub++;
			li.iItem = ListView_GetItemCount(hListRemind);
			li.iItem = ListView_InsertItem(hListRemind, &li);
            ListView_SetCheckState(hListRemind, li.iItem, !lpRemindItem[i].bNotUse);
			li.pszText = lpRemindItem[i].szFilter;
			li.iSubItem = iSub++;
			ListView_SetItem(hListRemind, &li);
			wsprintf(sz, L"%d", lpRemindItem[i].uMinPrice);
			li.pszText = sz;
			li.iSubItem = iSub++;
			ListView_SetItem(hListRemind, &li);
			wsprintf(sz, L"%d", lpRemindItem[i].uMaxPrice);
			li.pszText = sz;
			li.iSubItem = iSub++;
			ListView_SetItem(hListRemind, &li);
			if(lpRemindItem[i].szMemberID[0]!=L'\0')
                li.pszText = lpRemindItem[i].szMember;
            else
                li.pszText = szBus[lpRemindItem[i].iBusiness];
			li.iSubItem = iSub++;
			ListView_SetItem(hListRemind, &li);
/*
			wsprintf(sz, L"%d", lpRemindItem[i].iBusiness);
			li.pszText = sz;
			li.iSubItem = iSub++;
			ListView_SetItem(hListRemind, &li);
*/
		}        
    }
    else
        ShowWindow(hMain, SW_SHOW);
    hGetDataThread = CreateThread(NULL, 0, GetDataThreadProc, 0, 0, 0);    
    if (RemindSave.bTips)
        LoadToast();
/*
    WinToast::isCompatible();
	WinToast::instance()->setAppName(szAppName);
	WinToast::instance()->setAppUserModelId(szAppName);
	bNewTrayTips = WinToast::instance()->initialize();
*/
    bInit = FALSE;
    return TRUE;
}

//
//  函数: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  目标: 处理主窗口的消息。
//
//  WM_COMMAND  - 处理应用程序菜单
//  WM_PAINT    - 绘制主窗口
//  WM_DESTROY  - 发送退出消息并返回
//
//
LRESULT CALLBACK MainProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_INITDIALOG:
    {
    }
    return TRUE;
/*
    case WM_TIMER:
        if (wParam==3||wParam==6)
        {
			if (wParam == 6)
				KillTimer(hWnd, wParam);
            SetWindowText(hMain, L"正在从网站获取并处理数据请稍后...");
            if(IsWindowVisible(hMain))
                SetCursor(LoadCursor(NULL,IDC_WAIT));
            int n = riSize / sizeof REMINDITEM;
            for (int i=0;i<n;i++)
            {
                if(!lpRemindItem[i].bNotUse)
                    SearchSMZDM(&lpRemindItem[i], FALSE,FALSE);
            }
            WriteSet(NULL);
            SetWindowText(hMain,nid.szTip);
            SetCursor(LoadCursor(NULL, IDC_ARROW));
            bOpen = TRUE;
            return TRUE;
        }
        break;
*/
    case WM_IAWENTRAY:
//        if (HIWORD(lParam) == nid.uID)
        {
        if (LOWORD(lParam) == WM_LBUTTONDOWN)
        {
            SetFocus(GetDlgItem(hMain, IDC_KEY));
            ShowWindow(hMain, SW_SHOW);
            SetForeground(hMain);
            bInit = FALSE;
        }
        else if (LOWORD(lParam) == WM_RBUTTONDOWN)
            ItemToHtml(FALSE);
            else if (LOWORD(lParam) == NIN_BALLOONUSERCLICK && !RemindSave.bDirectly)
            {
                WCHAR sz[128];
                wsprintf(sz, L"https://www.smzdm.com/p/%d", nid.uID);
                ShellExecute(NULL, L"open", sz, NULL, NULL, SW_SHOW);
            }
        }
        return TRUE;
    case WM_NOTIFY:
    {
        if (bInit)
            return FALSE;
/*
        if (wParam == IDC_SYSLINK1||wParam==IDC_SYSLINK2)
        {
            LPNMHDR lpnh = (LPNMHDR)lParam;
            if (lpnh->code == NM_CLICK || lpnh->code == NM_RETURN)
            {
                CloseHandle(ShellExecute(NULL, L"open", L"http://810619.xyz:888/index.php?share/folder&user=1&sid=Zk2Ecwbt", NULL, NULL, SW_SHOW));
            }
        }
*/
        if (wParam == IDC_LIST)
        {
            LPNMITEMACTIVATE lnia = (LPNMITEMACTIVATE)lParam;
            if (lnia->iItem != -1)
            {
                if (lnia->hdr.code == NM_RCLICK)
                {
                    WCHAR sz[256];
                    if (lnia->iSubItem == 11)
                    {
                        ListView_GetItemText(hList, lnia->iItem, 11, sz, 256);
                    }
                    else if(lnia->iSubItem==9&& IsDlgButtonChecked(hWnd, IDC_CHECK_POST))
                    {
                        WCHAR sz[128];
//                        WCHAR szMember[12];
                        ListView_GetItemText(hList, lnia->iItem, 9, sz, 126);
//						GetMember(sz, szMember);
						SetDlgItemText(hWnd, IDC_EDIT_MEMBER, sz);
                        return FALSE;
                    }
                    else if (lnia->iSubItem == 8)
                    {
                        WCHAR wTitle[129], wDescripe[513], szLink[129], szImg[129];
                        ListView_GetItemText(hList, lnia->iItem, 0, wTitle, 128);
                        ListView_GetItemText(hList, lnia->iItem, 1, wDescripe, 512);
                        ListView_GetItemText(hList, lnia->iItem, 10, szLink, 128);
                        ListView_GetItemText(hList, lnia->iItem, 3, szImg, 128);
						if (RemindSave.bBark)
						{
							SendBark(RemindSave.szBarkUrl, RemindSave.szBarkSound, wTitle, wDescripe, szLink, szImg);
						}
						if (RemindSave.bDingDing)
						{
							SendDingDing(RemindSave.szDingDingToken, wTitle, wDescripe, szLink, szImg);
						}
						if (RemindSave.bWeChat)
						{
							SendWeChatPusher(RemindSave.szWeChatUserID, wTitle, wDescripe, szLink, szImg);
						}
						if (RemindSave.bWxPusher)
						{
							SendWxPusher(RemindSave.szWxPusherUID, wTitle, wDescripe, szLink, szImg);
						}
                        if (RemindSave.bTips)
                        {
                            if (bNewTrayTips)
                            {
                                CreateDirectory(L"cache", NULL);
                                WCHAR wImg[MAX_PATH];
                                GetCurrentDirectory(MAX_PATH, wImg);
                                lstrcat(wImg, L"\\cache\\");
                                WCHAR* wFileLeft = lstrstr(szImg + 2, L"/");;
                                while (true)
                                {
                                    wFileLeft += 1;
                                    WCHAR* wFileRight = lstrstr(wFileLeft, L"/");
                                    if (!wFileRight)
                                        break;
                                    else
                                        wFileLeft = wFileRight;
                                }
                                lstrcat(wImg, wFileLeft);
                                winhttpDownload(szImg, wImg);
                                ShowToast(wTitle, wDescripe, wImg, szLink);
                            }
                            else
                            {
                                nid.uFlags = NIF_MESSAGE | NIF_INFO | NIF_TIP | NIF_ICON;
                                //                            nid.dwState = NIS_SHAREDICON;
                                //                            nid.dwStateMask = NIS_SHAREDICON;
                                //							nid.uVersion = NOTIFYICON_VERSION_4;
                                //							nid.hBalloonIcon = iMain;
                                nid.dwInfoFlags = NIIF_NONE;
                                //                            nid.uID = tid;
                                nid.uTimeout = 0;
                                lstrcpyn(nid.szInfoTitle, wTitle, 63);
                                lstrcpyn(nid.szInfo, wDescripe, 255);
                                Shell_NotifyIcon(NIM_MODIFY, &nid);
                                //                            Shell_NotifyIcon(NIM_SETVERSION, &nid);
                            }

                        }
                        return FALSE;
                    }
                    else
                    {
                        ListView_GetItemText(hList, lnia->iItem, 10, sz, 256);
                    }
                    ShellExecute(NULL, L"open", sz, NULL, NULL, SW_SHOW);
                }
            }
            else
            {
				if (lnia->hdr.code == LVN_COLUMNCLICK)
				{
                    if (lnia->iSubItem == 4 || lnia->iSubItem == 6 || lnia->iSubItem == 7)
                        bSort = FALSE;
                    ListView_SortItemsEx(hList, CompareFunc, lnia->iSubItem);
                    bSort = !bSort;
//					ListView_SortItems(hList, CompareFunc, lnia->iSubItem);
				}
            }
        }
        else if (wParam == IDC_LIST_REMIND)
        {
            LPNMITEMACTIVATE lnia = (LPNMITEMACTIVATE)lParam;
            if (lnia->iItem == -1 || lnia->iItem > int(riSize / sizeof REMINDITEM))
                return FALSE;
            if (lnia->hdr.code == NM_RCLICK)
            {
                if (!bGetData)
                {
                    lpRemindItem[lnia->iItem].szKey[0] = L'\0';
                    lpRemindItem[lnia->iItem].szMemberID[0] = L'\0';
                    ListView_DeleteItem(hListRemind, lnia->iItem);
                    WriteSet(NULL);
                    ReadSet();
                }
            }
            else if (lnia->hdr.code == LVN_ITEMCHANGED)
            {
				DWORD o = lnia->uOldState & 0x2000;
				DWORD n = lnia->uNewState & 0x2000;
				if (o != n)
				{
					BOOL bCheck = ListView_GetCheckState(hListRemind, lnia->iItem);
					if (lpRemindItem[lnia->iItem].bNotUse == bCheck)
					{
						lpRemindItem[lnia->iItem].bNotUse = !bCheck;
						WriteSet(NULL);
					}
				}
                SetDlgItemText(hMain, IDC_KEY, lpRemindItem[lnia->iItem].szKey);
                SetDlgItemText(hMain, IDC_FILTER, lpRemindItem[lnia->iItem].szFilter);
                SetDlgItemInt(hMain, IDC_EDIT_MIN_PRICE, lpRemindItem[lnia->iItem].uMinPrice,FALSE);
                SetDlgItemInt(hMain, IDC_EDIT_MAX_PRICE, lpRemindItem[lnia->iItem].uMaxPrice,FALSE);
                SendMessage(hCombo, CB_SETCURSEL, lpRemindItem[lnia->iItem].iBusiness, NULL);
                SetDlgItemText(hMain, IDC_EDIT_MEMBER, lpRemindItem[lnia->iItem].szMemberID);
                CheckDlgButton(hMain, IDC_CHECK_POST, lpRemindItem[lnia->iItem].bMemberPost);
                SendMessage(hComboSendMode, CB_SETCURSEL, lpRemindItem[lnia->iItem].iSend, NULL);
                SetDlgItemInt(hMain, IDC_EDIT_ZHI, lpRemindItem[lnia->iItem].uZhi, FALSE);
                SetDlgItemInt(hMain, IDC_EDIT_BUZHI, lpRemindItem[lnia->iItem].uBuZhi, FALSE);
                int x = 0;
                if(lpRemindItem[lnia->iItem].uPercentage!=0)
                    x = lpRemindItem[lnia->iItem].uPercentage /10-4;
                SendMessage(hComBoPercentage, CB_SETCURSEL, x, NULL);
                SetDlgItemInt(hMain, IDC_EDIT_TALK, lpRemindItem[lnia->iItem].uTalk, FALSE);
                CheckDlgButton(hMain, IDC_CHECK_SCORE, lpRemindItem[lnia->iItem].bScore);
//                SetDlgItemInt(hMain, IDC_EDIT_PERCENTAGE, lpRemindItem[lnia->iItem].uPercentage, FALSE);
            }
        }
    }
    break;
    case WM_COMMAND:
    {
        int wmId = LOWORD(wParam);
        // 分析菜单选择:
        switch (wmId)
        {
        case IDC_VIEW_LOG:
        {
            HWND hListRemind, hListLog;
            hListRemind = GetDlgItem(hWnd, IDC_LIST_REMIND);
            hListLog = GetDlgItem(hWnd, IDC_LIST_LOG);
            if (IsWindowVisible(hListRemind))
            {
                ShowWindow(hListRemind, SW_HIDE);
                ShowWindow(hListLog, SW_SHOW);
                ShowWindow(GetDlgItem(hWnd, IDC_STATIC1), SW_SHOW);
                ShowWindow(GetDlgItem(hWnd, IDC_STATIC2), SW_SHOW);
                ShowWindow(GetDlgItem(hWnd, IDC_STATIC3), SW_SHOW);
                ShowWindow(GetDlgItem(hWnd, IDC_STATIC4), SW_SHOW);
                ShowWindow(GetDlgItem(hWnd, IDC_STATIC5), SW_SHOW);
                ShowWindow(GetDlgItem(hWnd, IDC_STATIC6), SW_SHOW);
                ShowWindow(GetDlgItem(hWnd, IDC_EDIT1), SW_SHOW);
                ShowWindow(GetDlgItem(hWnd, IDC_EDIT2), SW_SHOW);
                ShowWindow(GetDlgItem(hWnd, IDC_EDIT3), SW_SHOW);
                ShowWindow(GetDlgItem(hWnd, IDC_EDIT4), SW_SHOW);
                ShowWindow(GetDlgItem(hWnd, IDC_EDIT5), SW_SHOW);
                ShowWindow(GetDlgItem(hWnd, IDC_EDIT6), SW_SHOW);
                ShowWindow(GetDlgItem(hWnd, IDC_BUTTON_SAVE_COOKIE), SW_SHOW);
            }
            else
            {
                ShowWindow(hListLog, SW_HIDE);
                ShowWindow(GetDlgItem(hWnd, IDC_STATIC1), SW_HIDE);
                ShowWindow(GetDlgItem(hWnd, IDC_STATIC2), SW_HIDE);
                ShowWindow(GetDlgItem(hWnd, IDC_STATIC3), SW_HIDE);
                ShowWindow(GetDlgItem(hWnd, IDC_STATIC4), SW_HIDE);
                ShowWindow(GetDlgItem(hWnd, IDC_STATIC5), SW_HIDE);
                ShowWindow(GetDlgItem(hWnd, IDC_STATIC6), SW_HIDE);
                ShowWindow(GetDlgItem(hWnd, IDC_EDIT1), SW_HIDE);
                ShowWindow(GetDlgItem(hWnd, IDC_EDIT2), SW_HIDE);
                ShowWindow(GetDlgItem(hWnd, IDC_EDIT3), SW_HIDE);
                ShowWindow(GetDlgItem(hWnd, IDC_EDIT4), SW_HIDE);
                ShowWindow(GetDlgItem(hWnd, IDC_EDIT5), SW_HIDE);
                ShowWindow(GetDlgItem(hWnd, IDC_EDIT6), SW_HIDE);
                ShowWindow(GetDlgItem(hWnd, IDC_BUTTON_SAVE_COOKIE), SW_HIDE);
                ShowWindow(hListRemind, SW_SHOW);
            }
        };
        break;
        case IDC_BUTTON_SAVE_COOKIE:
            WCHAR wCookie[CookieSize];
            GetDlgItemText(hMain, IDC_EDIT1, wCookie, CookieSize - 1);
            WriteCookieToFile(2, wCookie);
            GetDlgItemText(hMain, IDC_EDIT2, wCookie, CookieSize - 1);
            WriteCookieToFile(3, wCookie);
            GetDlgItemText(hMain, IDC_EDIT3, wCookie, CookieSize - 1);
            WriteCookieToFile(4, wCookie);
            GetDlgItemText(hMain, IDC_EDIT4, wCookie, CookieSize - 1);
            WriteCookieToFile(5, wCookie);
            GetDlgItemText(hMain, IDC_EDIT5, wCookie, CookieSize - 1);
            WriteCookieToFile(6, wCookie);
            GetDlgItemText(hMain, IDC_EDIT6, wCookie, CookieSize - 1);
            WriteCookieToFile(7, wCookie);
            break;
        case IDC_SIGN_IN1:
        case IDC_SIGN_IN2:
        {
                WCHAR wCookie[CookieSize];
                wCookie[0] = L'\0';
                int nDay = 0;
                if (wmId == IDC_SIGN_IN1)
                {
                    if (lParam != 1)
                    {
                        GetDlgItemText(hMain, IDC_COOKIE1, wCookie, CookieSize - 1);
                        WriteCookieToFile(0, wCookie);
                    }
                    else
                        ReadCookieFromFile(0, wCookie);
                }
                else
                {
                    if (lParam != 1)
                    {
                        GetDlgItemText(hMain, IDC_COOKIE2, wCookie, CookieSize - 1);
                        WriteCookieToFile(1, wCookie);
                    }
                    else
                    {
                        ReadCookieFromFile(1, wCookie);
                    }
                }
                if (wCookie[0] != L'\0')
                {
                    if(lParam==1)
                        SetWindowText(hMain, L"正在签到---什么值得买...");
                    nDay = SignSMZDM(wCookie);
                    if (nDay == 99)
                    {
                        SetDlgItemText(hWnd, wmId, L"Cookie失效！");
                    }
                    else
                    {
                        WCHAR szText[32];
                        if (nDay >= 0)
                            wsprintf(szText, L"已签到%d天", nDay);
                        else
                            wsprintf(szText, L"错误码%d", nDay);
                        SetDlgItemText(hWnd, wmId, szText);
                    }
                }
        }
        break;
        case IDC_BUTTON_LINK1:
        case IDC_BUTTON_LINK2:
        case IDC_BUTTON_LINK3:
        case IDC_BUTTON_LINK4:
        case IDC_BUTTON_LINK5:
        case IDC_BUTTON_LINK6:
        case IDC_BUTTON_LINK7:
        case IDC_BUTTON_LINK8:
        {
            WCHAR szLink[][64] = { L"https://faxian.smzdm.com/9kuai9/h4s0t0f0p1/#filter-block",L"https://faxian.smzdm.com/h2s0t0f0c0p1/#filter-block",L"https://faxian.smzdm.com/h3s0t0f0c0p1/#filter-block",L"https://faxian.smzdm.com/h4s0t0f0c0p1/#filter-block",L"https://post.smzdm.com/",L"https://post.smzdm.com/hot_7/",L"https://test.smzdm.com/",L"https://duihuan.smzdm.com/" };
            ShellExecute(NULL, L"open", szLink[wmId - IDC_BUTTON_LINK1], NULL, NULL, SW_SHOW);
        }
        break;
        case IDC_HISTORY:
        {
            int nSearch = (int)SendMessage(hComboSearch, CB_GETCURSEL, 0, 0);
            if (nSearch == 1)
                ItemToHtml(FALSE);
            ListView_DeleteAllItems(hList);
            HANDLE hFile = CreateFile(szRemindItem, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_ARCHIVE, NULL);
            if (hFile != INVALID_HANDLE_VALUE)
            {
                while (TRUE)
                {
                    DWORD dwBytes = 0;
                    SMZDMITEM SmzdmItem;
                    ReadFile(hFile, &SmzdmItem, sizeof SMZDMITEM, &dwBytes, NULL);
                    if (dwBytes == 0)
                    {
                        CloseHandle(hFile);
                        break;
                    }
                    WCHAR sz[64];
                    LVITEM li = { 0 };
                    int iSub = 0;
                    li.mask = LVIF_TEXT;
                    li.pszText = SmzdmItem.szTitle;
                    li.iSubItem = iSub++;
                    li.iItem = 0;
                    li.iItem = ListView_InsertItem(hList, &li);
                    li.pszText = SmzdmItem.szDescribe;
                    li.iSubItem = iSub++;
                    //                    ListView_SetItem(hList, &li);
                    int p = int(SmzdmItem.fPrice * 100);
                    wsprintf(sz, L"%d.%2.2d", p / 100, p % 100);
                    li.pszText = sz;
                    li.iSubItem = iSub++;
                    ListView_SetItem(hList, &li);
                    li.pszText = SmzdmItem.szImg;
                    li.iSubItem = iSub++;
                    ListView_SetItem(hList, &li);
                    wsprintf(sz, L"%d", SmzdmItem.lZhi);
                    li.pszText = sz;
                    li.iSubItem = iSub++;
                    ListView_SetItem(hList, &li);
                    wsprintf(sz, L"%d", SmzdmItem.lBuZhi);
                    li.pszText = sz;
                    li.iSubItem = iSub++;
                    ListView_SetItem(hList, &li);
                    wsprintf(sz, L"%d", SmzdmItem.lStar);
                    li.pszText = sz;
                    li.iSubItem = iSub++;
                    ListView_SetItem(hList, &li);
                    wsprintf(sz, L"%d", SmzdmItem.lTalk);
                    li.pszText = sz;
                    li.iSubItem = iSub++;
                    ListView_SetItem(hList, &li);
                    wsprintf(sz, L"%d-%2.2d-%2.2d %2.2d:%2.2d", SmzdmItem.st.wYear, SmzdmItem.st.wMonth, SmzdmItem.st.wDay, SmzdmItem.st.wHour, SmzdmItem.st.wMinute);
                    li.pszText = sz;
                    li.iSubItem = iSub++;
                    ListView_SetItem(hList, &li);
                    li.pszText = SmzdmItem.szBusiness;
                    li.iSubItem = iSub++;
                    ListView_SetItem(hList, &li);
                    li.pszText = SmzdmItem.szLink;
                    li.iSubItem = iSub++;
                    ListView_SetItem(hList, &li);
                    li.pszText = SmzdmItem.szGoPath;
                    li.iSubItem = iSub++;
                    ListView_SetItem(hList, &li);

                    }
                }
                break;
            }
/*
            case IDC_BUTTON_MEMBER:
            {
                WCHAR szMember[12];
                WCHAR szKey[129];
                GetDlgItemText(hWnd, IDC_EDIT_MEMBER, szKey, 128);
                GetMember(szKey, szMember);
                SetDlgItemText(hWnd, IDC_EDIT_MEMBER, szMember);
            }
                break;
*/
            case IDC_REMIND:
            case IDC_OUR_REMIND:
            case IDC_SEARCH:
            {
                bInit = TRUE;
                REMINDITEM ri={0};
                WCHAR sz[128];
				GetDlgItemText(hWnd, IDC_EDIT_MEMBER, sz, 128);
                BOOL bID = FALSE;
                if (lstrlen(sz) == 10)
                {
                    for (int i=0;i<10;i++)
                    {
                        if (sz[i] < L'0' && sz[i] > L'9')
                            break;
                        if (i == 9)
                            bID = TRUE;
                    }
                }           
                if (bID)
                    lstrcpy(ri.szMemberID, sz);
                else if(lstrlen(sz))
                    GetMember(sz, ri.szMemberID);
                lstrcpyn(ri.szMember, sz,13);
                sz[0] = L'\0';
                GetDlgItemText(hWnd, IDC_KEY, sz, 128);
                WCHAR *szKey = sz;
				while (szKey[0] == L' ')
				{
					szKey++;
				}
				if (lstrlen(szKey) == 0&&lstrlen(ri.szMemberID)==0)
					return FALSE;
                lstrcpy(ri.szKey, szKey);
                GetDlgItemText(hWnd, IDC_FILTER, sz, 128);
                WCHAR* szFilter = sz;
                while (szFilter[0]==L' ')
                {
                    szFilter++;
                }
                lstrcpy(ri.szFilter, sz);
                ri.iBusiness = (int)SendMessage(hCombo, CB_GETCURSEL, NULL, NULL);
                ri.bMemberPost = IsDlgButtonChecked(hWnd, IDC_CHECK_POST);
                ri.bScore = IsDlgButtonChecked(hWnd, IDC_CHECK_SCORE);
                ri.uMinPrice = GetDlgItemInt(hWnd, IDC_EDIT_MIN_PRICE, NULL, FALSE);
                ri.uMaxPrice = GetDlgItemInt(hWnd, IDC_EDIT_MAX_PRICE, NULL, FALSE);
                ri.iSend = (int)SendMessage(hComboSendMode, CB_GETCURSEL, NULL, NULL);                
                ri.uZhi = GetDlgItemInt(hWnd, IDC_EDIT_ZHI, NULL, FALSE);
                ri.uBuZhi = GetDlgItemInt(hWnd, IDC_EDIT_BUZHI, NULL, FALSE);
                ri.uPercentage = (int)SendMessage(hComBoPercentage, CB_GETCURSEL, NULL, NULL);
            BOOL bGrey = IsDlgButtonChecked(hWnd, IDC_CHECK_GREY);
                if (ri.uPercentage != 0)
                    ri.uPercentage = ri.uPercentage * 10 + 40;
//                ri.uPercentage = GetDlgItemInt(hWnd, IDC_EDIT_PERCENTAGE, NULL, FALSE);
                ri.uTalk = GetDlgItemInt(hWnd, IDC_EDIT_TALK, NULL, FALSE);
                int nSearch=(int)SendMessage(hComboSearch, CB_GETCURSEL, 0, 0);
                if (nSearch==2)
                {
                    SearchSMZDM(&ri, TRUE, 0, TRUE,bGrey);
                }
                else if (wmId == IDC_SEARCH)
                {
                    SearchSMZDM(&ri, TRUE, 0,FALSE,bGrey);
                    int n = (int)SendMessage(hComboPage, CB_GETCURSEL, NULL, NULL);
                    for (int i = 1; i <= n; i++)
                    {
                        SearchSMZDM(&ri, TRUE, i + 1,FALSE,bGrey);
                    }
                    if (ri.szMemberID[0] != L'\0')
                    {
                        UINT nCount = ListView_GetItemCount(hList);
                        for (UINT i=0;i<nCount;i++)
                        {
                            CloseHandle(CreateThread(NULL, 0, GetZhiThreadProc, (PVOID)i, 0, 0));
                        }
                        
                    }
                    if(nSearch==1)
                        ItemToHtml(TRUE);
                }
                else if (!bGetData)
                {
                    LVITEM li = { 0 };
                    li.mask = LVIF_TEXT;
                    int cur = ListView_GetNextItem(hListRemind, -1, LVNI_SELECTED);
                    int iSub = 0;
                    li.pszText = ri.szKey;
                    li.iSubItem = iSub;
                    if (wmId == IDC_OUR_REMIND && cur != -1)
                    {
                        li.iItem = cur;
                        ListView_SetItem(hListRemind, &li);
                    }
                    else
                    {                                                
                        li.iItem = ListView_GetItemCount(hListRemind);
                        li.iItem = ListView_InsertItem(hListRemind, &li);
                        ListView_SetCheckState(hListRemind, li.iItem, TRUE);
                    }
                    iSub++;
                    li.pszText = ri.szFilter;
                    li.iSubItem = iSub++;
                    ListView_SetItem(hListRemind, &li);
                    wsprintf(sz, L"%d", ri.uMinPrice);
                    li.pszText = sz;
                    li.iSubItem = iSub++;
                    ListView_SetItem(hListRemind, &li);
                    wsprintf(sz, L"%d", ri.uMaxPrice);
                    li.pszText = sz;
                    li.iSubItem = iSub++;
                    ListView_SetItem(hListRemind, &li);
                    if(ri.szMemberID[0]!=L'\0')
                        li.pszText = ri.szMember;
                    else
                        li.pszText = szBus[ri.iBusiness];
                    li.iSubItem = iSub++;
                    ListView_SetItem(hListRemind, &li);
                    if (wmId == IDC_OUR_REMIND && cur != -1)
                    {
//                        ri.uid = lpRemindItem[cur].uid;
                        lstrcpy(ri.szID, lpRemindItem[cur].szID);
                        memcpy(ri.oldID, lpRemindItem[cur].oldID, sizeof ri.oldID);
                        ri.n = lpRemindItem[cur].n;
                        ri.bNotUse = lpRemindItem[cur].bNotUse;
                        lpRemindItem[cur] = ri;
                        WriteSet(NULL);
                    }
                    else
                    {
                        WriteSet(&ri);
                        ListView_SetItemState(hListRemind, li.iItem, LVIS_SELECTED, LVIS_SELECTED);
                    }
                    ReadSet();
                }
                bInit = FALSE;
            }
            break;
            case IDC_SAVE:
                RemindSave.bDirectly = IsDlgButtonChecked(hWnd, IDC_CHECK_OPEN_LINK);
                RemindSave.bWxPusher = IsDlgButtonChecked(hWnd, IDC_CHECK_WXPUSHER);
                RemindSave.bTips = IsDlgButtonChecked(hWnd, IDC_CHECK_TIPS);
                if (RemindSave.bTips)
                {
                    if (!hWintoast)
                        LoadToast();
                }
                else
                {
                    if (hWintoast)
                    {
                        FreeLibrary(hWintoast);
                        bNewTrayTips = FALSE;
                    }
                }
                GetDlgItemText(hWnd, IDC_UID, RemindSave.szWxPusherUID, 63);
                RemindSave.bWeChat = IsDlgButtonChecked(hWnd, IDC_CHECK_WECHAT);
                GetDlgItemText(hWnd, IDC_WECHAT_AID, RemindSave.szWeChatAgentId, 8);
                GetDlgItemText(hWnd, IDC_WECHAT_CORPID, RemindSave.szWeChatID, 24);
                GetDlgItemText(hWnd, IDC_WECHAT_SECRET, RemindSave.szWeChatSecret, 48);
                GetDlgItemText(hWnd, IDC_WECHAT_UID, RemindSave.szWeChatUserID, 64);
                RemindSave.bDingDing = IsDlgButtonChecked(hWnd, IDC_CHECK_DINGDING);
                GetDlgItemText(hWnd, IDC_ACCESS_TOKEN, RemindSave.szDingDingToken, 80);
                RemindSave.bBark = IsDlgButtonChecked(hWnd, IDC_CHECK_BARK);
                GetDlgItemText(hWnd, IDC_BARK_URL, RemindSave.szBarkUrl, 138);
                GetDlgItemText(hWnd, IDC_COMBO_SOUND, RemindSave.szBarkSound, 28);
                RemindSave.bScoreSort = IsDlgButtonChecked(hWnd, IDC_CHECK_SCORE);                
                RemindSave.iTime = (int)SendMessage(hComboTime, CB_GETCURSEL, NULL, NULL);
                RemindSave.iPage = (int)SendMessage(hComboPage, CB_GETCURSEL, NULL, NULL);
                WriteSet(NULL);
            GetDlgItemText(hMain, IDC_COOKIE1, wCookie, CookieSize - 1);
            WriteCookieToFile(0, wCookie);
            GetDlgItemText(hMain, IDC_COOKIE2, wCookie, CookieSize - 1);
            WriteCookieToFile(1, wCookie);
/*
                KillTimer(hMain, 3);
                SetTimer(hMain, 3, iTimes[RemindSave.iTime] * 60000, NULL);
                SetTimer(hMain, 6, 8888, NULL);
*/
                bResetTime = TRUE;
                break;
            case IDC_CHECK_AUTORUN:
                AutoRun(TRUE, IsDlgButtonChecked(hWnd, IDC_CHECK_AUTORUN), szAppName);
                break;
            case IDC_EXIT:
                if (MessageBox(hMain, L"确定要退出？退出后将无法推送！", L"提示", MB_OKCANCEL | MB_ICONQUESTION) == IDOK)
                {
                    DestroyWindow(hWnd);
                    lpRemindData->bExit = TRUE;
                }
                break;
            case IDCLOSE:
            case IDCANCEL:
                EmptyProcessMemory(NULL);
                ListView_DeleteAllItems(hList);
                ShowWindow(hWnd, SW_HIDE);
                break;
            default:
                return FALSE;
            }
        }
        return TRUE;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    }
    return (INT_PTR)FALSE;
}
