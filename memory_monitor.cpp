#include <direct.h>
#include <io.h>
#include <math.h>
#include <string.h>
#include <time.h>
#include <atomic>
#include <exception>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include "cmdline/cmdline.h"
#include "logger/Logger.h"
#include <xlnt/xlnt.hpp>
/* 下面头文件在最后面包含 */
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#pragma comment(lib, "psapi.lib")

#define VERSION "1.0"

std::atomic_bool g_isInit = true;
std::atomic_int32_t g_preWorkingSetSizeKb = 0;
std::atomic_int32_t g_preWorkSetPrivateKb = 0;
std::atomic_int32_t g_preWorkSetSharedKb = 0;

xlnt::workbook g_excel;
xlnt::worksheet g_excelSheet = g_excel.active_sheet();
std::string g_excelFilename;	/* excel文件名 */
std::atomic_ulong g_excelIndex = 2;	/* 由于标题占用了2行, 所以这里需要从第3行开始 */
std::recursive_mutex m_excelMutex;

unsigned long long generateUID(void) {
	static int sY = 0, sM = 0, sD = 0, sH = 0, sMM = 0, sS = 0, sIdx = 1;
	time_t t = time(nullptr);
	struct tm* dt = localtime(&t);
	int year = 1900 + dt->tm_year, mon = 1 + dt->tm_mon, mday = dt->tm_mday, hour = dt->tm_hour, min = dt->tm_min, sec = dt->tm_sec;
	if (year == sY && mon == sM && mday == sD && hour == sH && min == sMM && sec == sS) {
		sIdx++;
	}
	else {
		sY = year; sM = mon; sD = mday; sH = hour; sMM = min; sS = sec; sIdx = 1;
	}
	return (unsigned long long)sY * 10000000000000 + (unsigned long long)sM * 100000000000 + (unsigned long long)sD * 1000000000 +
		(unsigned long long)sH * 10000000 + (unsigned long long)sMM * 100000 + (unsigned long long)sS * 1000 + (unsigned long long)sIdx;
}

std::string generateFilename(const std::string& extname) {
	char filename[64] = { 0 };
	sprintf(filename, "%llu%s", generateUID(), extname.empty() ? "" : ('.' == extname.at(0) ? extname.c_str() : ('.' + extname).c_str()));
	return filename;
}

/* 提升进程权限 */
bool adjustPurview() {
	TOKEN_PRIVILEGES tokenPrivileges;
	HANDLE hToken;

	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tokenPrivileges.Privileges[0].Luid);
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);

	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	BOOL ret = AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, 0, NULL, NULL);

	CloseHandle(hToken);
	return (TRUE == ret);
}

/* 查询进程信息 */
void queryProcessInfo(unsigned long processId,
	unsigned long& workingSetSize, unsigned long& workSetPrivate, unsigned long& workSetShared,
	unsigned long& handles,
	unsigned long& threads) {
	workingSetSize = workSetPrivate = workSetShared = 0;
	handles = 0;
	threads = 0;
	adjustPurview();
	/* 获取进程句柄 */
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
	if (!hProcess) {
		return;
	}
	/* 查询工作集(内存) */
	PROCESS_MEMORY_COUNTERS pmc;
	GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc));
	if (0 == pmc.QuotaPagedPoolUsage && 0 == pmc.QuotaNonPagedPoolUsage) {	/* 视为进程退出 */
		CloseHandle(hProcess);
		return;
	}
	workingSetSize = pmc.WorkingSetSize; /* 工作集(内存)(单位:字节): 进程当前正在使用的物理内存量, =内存(专用工作集)+内存(共享工作集) */
	/* 获取系统分页大小(单位:字节) */
	static SIZE_T s_pageSize = 0;
	if (0 == s_pageSize) {
		PERFORMANCE_INFORMATION performanceInfo;
		memset(&performanceInfo, 0, sizeof(performanceInfo));
		if (GetPerformanceInfo(&performanceInfo, sizeof(performanceInfo))) {
			s_pageSize = performanceInfo.PageSize;
		}
	}
	/* 查询工作集 */
	if (s_pageSize > 0) {
		PSAPI_WORKING_SET_INFORMATION workSetInfo;
		memset(&workSetInfo, 0, sizeof(workSetInfo));
		PSAPI_WORKING_SET_BLOCK* workSetBlock = workSetInfo.WorkingSetInfo;
		PBYTE pByte = NULL;
		BOOL queryRet = TRUE;
		if (!QueryWorkingSet(hProcess, &workSetInfo, sizeof(workSetInfo))) {	/* 获取实际缓冲区大小 */
			if (ERROR_BAD_LENGTH == GetLastError()) {	/* 需要重新分配缓冲区 */
				DWORD realSize = sizeof(workSetInfo.NumberOfEntries) + workSetInfo.NumberOfEntries * sizeof(PSAPI_WORKING_SET_BLOCK);
				try {
					pByte = new BYTE[realSize];
					memset(pByte, 0, realSize);
					workSetBlock = (PSAPI_WORKING_SET_BLOCK*)(pByte + sizeof(workSetInfo.NumberOfEntries));
					if (!QueryWorkingSet(hProcess, pByte, realSize))	/* 重新查询 */
					{
						queryRet = FALSE;
					}
				}
				catch (char* e) {	/* 内存分配失败 */
					(void)e;
					queryRet = FALSE;
				}
				catch (...) {
					queryRet = FALSE;
				}
			}
			else {
				queryRet = FALSE;
			}
		}
		if (queryRet) {
			for (ULONG_PTR i = 0; i < workSetInfo.NumberOfEntries; ++i)
			{
				if (workSetBlock[i].Shared) {	/* 共享页 */
					workSetShared += s_pageSize;	/* 内存(共享工作集): 由该进程所使用且可与其他进程共享的物理内存量 */
				}
				else {	/* 非共享页 */
					workSetPrivate += s_pageSize;	/* 内存(专用工作集): 由该进程所使用而其他进程无法使用的物理内存量 */
				}
			}
		}
		/* 需要最后清理内存, 否则会出错 */
		if (pByte) {
			delete[] pByte;
			pByte = NULL;
		}
	}
	/* 查询句柄数 */
	GetProcessHandleCount(hProcess, &handles);
	/* 查询线程数 */
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE != hProcessSnap)
	{
		char szFilePath[MAX_PATH] = { 0 };
		PROCESSENTRY32 stProcessEntry32 = { 0 };
		stProcessEntry32.dwSize = sizeof(stProcessEntry32);
		BOOL bSucceed = Process32First(hProcessSnap, &stProcessEntry32);;
		for (;;)
		{
			if (!bSucceed) {
				break;
			}
			if (stProcessEntry32.th32ProcessID == processId)
			{
				threads = stProcessEntry32.cntThreads;
				break;
			}
			bSucceed = Process32Next(hProcessSnap, &stProcessEntry32);
		}
		CloseHandle(hProcessSnap);
	}
	/* 关闭进程句柄 */
	CloseHandle(hProcess);
}

/* 保存excel文件 */
void saveExcelFile() {
	if (!g_excelFilename.empty()) {
		g_excel.save(g_excelFilename);
	}
}

/* 设置excel标题头 */
void setExcelHeader() {
	std::lock_guard<std::recursive_mutex> locker(m_excelMutex);
	/* 日期 */
	g_excelSheet.column_properties(xlnt::column_t("A")).width = 19.38;
	g_excelSheet.cell("A1").alignment(xlnt::alignment().horizontal(xlnt::horizontal_alignment::center).vertical(xlnt::vertical_alignment::center));
	g_excelSheet.cell("A1").font(xlnt::font().bold(true));
	g_excelSheet.cell("A1").value("Datetime");
	g_excelSheet.merge_cells("A1:A2");
	/* 内存 */
	g_excelSheet.column_properties(xlnt::column_t("B")).width = 14.75;
	g_excelSheet.cell("B1").alignment(xlnt::alignment().horizontal(xlnt::horizontal_alignment::center).vertical(xlnt::vertical_alignment::center));
	g_excelSheet.cell("B1").font(xlnt::font().bold(true));
	g_excelSheet.cell("B1").value("Memory(Mb)");
	g_excelSheet.merge_cells("B1:D1");
	/* 工作集(内存) */
	g_excelSheet.cell("B2").alignment(xlnt::alignment().horizontal(xlnt::horizontal_alignment::center).vertical(xlnt::vertical_alignment::center));
	g_excelSheet.cell("B2").font(xlnt::font().bold(true));
	g_excelSheet.cell("B2").value("WorkingSetSize");
	/* 内存(专用工作集) */
	g_excelSheet.column_properties(xlnt::column_t("C")).width = 14.38;
	g_excelSheet.cell("C2").alignment(xlnt::alignment().horizontal(xlnt::horizontal_alignment::center).vertical(xlnt::vertical_alignment::center));
	g_excelSheet.cell("C2").font(xlnt::font().bold(true));
	g_excelSheet.cell("C2").value("WorkSetPrivate");
	/* 内存(共享工作集) */
	g_excelSheet.column_properties(xlnt::column_t("D")).width = 14.5;
	g_excelSheet.cell("D2").alignment(xlnt::alignment().horizontal(xlnt::horizontal_alignment::center).vertical(xlnt::vertical_alignment::center));
	g_excelSheet.cell("D2").font(xlnt::font().bold(true));
	g_excelSheet.cell("D2").value("WorkSetShared");
	/* 句柄数 */
	g_excelSheet.column_properties(xlnt::column_t("E")).width = 7.88;
	g_excelSheet.cell("E1").alignment(xlnt::alignment().horizontal(xlnt::horizontal_alignment::center).vertical(xlnt::vertical_alignment::center));
	g_excelSheet.cell("E1").font(xlnt::font().bold(true));
	g_excelSheet.cell("E1").value("Handles");
	g_excelSheet.merge_cells("E1:E2");
	/* 线程数 */
	g_excelSheet.column_properties(xlnt::column_t("F")).width = 7.63;
	g_excelSheet.cell("F1").alignment(xlnt::alignment().horizontal(xlnt::horizontal_alignment::center).vertical(xlnt::vertical_alignment::center));
	g_excelSheet.cell("F1").font(xlnt::font().bold(true));
	g_excelSheet.cell("F1").value("Threads");
	g_excelSheet.merge_cells("F1:F2");
	/* 保存 */
	saveExcelFile();
}

/* 设置excel行内容 */
void setExcelRow(unsigned int index, int workingSetSizeKb, int diffWorkingSetSizeKb, int workSetPrivateKb, int diffWorkSetPrivateKb, int workSetSharedKb, int diffWorkSetSharedKb, int handes, int threads) {
	std::lock_guard<std::recursive_mutex> locker(m_excelMutex);
	/* 日期 */
	time_t now;
	time(&now);
	struct tm t = *localtime(&now);
	char datetime[22] = { 0 };
	strftime(datetime, sizeof(datetime), "%Y-%m-%d %H:%M:%S", &t);
	g_excelSheet.cell("A" + std::to_string(index)).alignment(xlnt::alignment().horizontal(xlnt::horizontal_alignment::center).vertical(xlnt::vertical_alignment::center));
	g_excelSheet.cell("A" + std::to_string(index)).value(datetime);
	/* 工作集(内存) */
	char workingSetSizeMbStr[32] = { 0 };
	sprintf_s(workingSetSizeMbStr, "%0.1f", (double)workingSetSizeKb / 1024);
	char workingSetSizeComment[128] = { 0 };
	if (3 == index || 0 == diffWorkingSetSizeKb) {	/* 第1行或者无差异 */
		sprintf_s(workingSetSizeComment, "(%d Kb)", workingSetSizeKb);
	}
	else {
		sprintf_s(workingSetSizeComment, "(%d Kb)\n%s%0.1f Mb\n(%d Kb)",
			workingSetSizeKb, (diffWorkingSetSizeKb > 0 ? "+" : "-"), (double)abs(diffWorkingSetSizeKb) / 1024, abs(diffWorkingSetSizeKb));
	}
	g_excelSheet.cell("B" + std::to_string(index)).alignment(xlnt::alignment().horizontal(xlnt::horizontal_alignment::center).vertical(xlnt::vertical_alignment::center));
	g_excelSheet.cell("B" + std::to_string(index)).number_format(xlnt::number_format::general());
	g_excelSheet.cell("B" + std::to_string(index)).value(std::atof(workingSetSizeMbStr));
	g_excelSheet.cell("B" + std::to_string(index)).comment(xlnt::comment(workingSetSizeComment, ""));
	/* 内存(专用工作集) */
	char workSetPrivateMbStr[32] = { 0 };
	sprintf_s(workSetPrivateMbStr, "%0.1f", (double)workSetPrivateKb / 1024);
	char workSetPrivateComment[128] = { 0 };
	if (3 == index || 0 == diffWorkSetPrivateKb) {	/* 第1行或者无差异 */
		sprintf_s(workSetPrivateComment, "(%d Kb)", workSetPrivateKb);
	}
	else {
		sprintf_s(workSetPrivateComment, "(%d Kb)\n%s%0.1f Mb\n(%d Kb)",
			workSetPrivateKb, (diffWorkSetPrivateKb > 0 ? "+" : "-"), (double)abs(diffWorkSetPrivateKb) / 1024, abs(diffWorkSetPrivateKb));
	}
	g_excelSheet.cell("C" + std::to_string(index)).alignment(xlnt::alignment().horizontal(xlnt::horizontal_alignment::center).vertical(xlnt::vertical_alignment::center));
	g_excelSheet.cell("C" + std::to_string(index)).number_format(xlnt::number_format::general());
	g_excelSheet.cell("C" + std::to_string(index)).value(std::atof(workSetPrivateMbStr));
	g_excelSheet.cell("C" + std::to_string(index)).comment(xlnt::comment(workSetPrivateComment, ""));
	/* 内存(共享工作集) */
	char workSetSharedMbStr[32] = { 0 };
	sprintf_s(workSetSharedMbStr, "%0.1f", (double)workSetSharedKb / 1024);
	char workSetSharedComment[128] = { 0 };
	if (3 == index || 0 == diffWorkSetSharedKb) {	/* 第1行或者无差异 */
		sprintf_s(workSetSharedComment, "(%d Kb)", workSetSharedKb);
	}
	else {
		sprintf_s(workSetSharedComment, "(%d Kb)\n%s%0.1f Mb\n(%d Kb)",
			workSetSharedKb, (diffWorkSetSharedKb > 0 ? "+" : "-"), (double)abs(diffWorkSetSharedKb) / 1024, abs(diffWorkSetSharedKb));
	}
	g_excelSheet.cell("D" + std::to_string(index)).alignment(xlnt::alignment().horizontal(xlnt::horizontal_alignment::center).vertical(xlnt::vertical_alignment::center));
	g_excelSheet.cell("D" + std::to_string(index)).number_format(xlnt::number_format::general());
	g_excelSheet.cell("D" + std::to_string(index)).value(std::atof(workSetSharedMbStr));
	g_excelSheet.cell("D" + std::to_string(index)).comment(xlnt::comment(workSetSharedComment, ""));
	/* 句柄数 */
	g_excelSheet.cell("E" + std::to_string(index)).alignment(xlnt::alignment().horizontal(xlnt::horizontal_alignment::center).vertical(xlnt::vertical_alignment::center));
	g_excelSheet.cell("E" + std::to_string(index)).value(handes);
	/* 线程数 */
	g_excelSheet.cell("F" + std::to_string(index)).alignment(xlnt::alignment().horizontal(xlnt::horizontal_alignment::center).vertical(xlnt::vertical_alignment::center));
	g_excelSheet.cell("F" + std::to_string(index)).value(threads);
	/* 保存 */
	saveExcelFile();
}

/* 设置excel标记 */
void setExcelTag(unsigned int index, const std::string& tag) {
	std::lock_guard<std::recursive_mutex> locker(m_excelMutex);
	/* 标记拼接 */
	std::string newTag = g_excelSheet.cell("G" + std::to_string(index)).to_string();
	newTag += (newTag.empty() ? "" : ",") + tag;
	g_excelSheet.cell("G" + std::to_string(index)).alignment(xlnt::alignment().horizontal(xlnt::horizontal_alignment::center).vertical(xlnt::vertical_alignment::center));
	g_excelSheet.cell("G" + std::to_string(index)).fill(xlnt::fill::solid(xlnt::color(xlnt::rgb_color(255, 192, 0))));	/* 标记单元格用颜色填充 */
	g_excelSheet.cell("G" + std::to_string(index)).value(newTag);
	/* 保存 */
	saveExcelFile();
}

/* 统计分析 */
bool statisticalAnalysis(unsigned int pid, unsigned int memorySize, bool force) {
	unsigned long workingSetSize, workSetPrivate, workSetShared;
	unsigned long handles;
	unsigned long threads;
	queryProcessInfo(pid, workingSetSize, workSetPrivate, workSetShared, handles, threads);
	if (0 == workingSetSize) {
		return false;
	}
	if (0 == workSetPrivate || 0 == workSetShared) {
		return true;
	}
	/* 字节转Kb */
	int workingSetSizeKb = workingSetSize / 1024;
	int workSetPrivateKb = workSetPrivate / 1024;
	int workSetSharedKb = workSetShared / 1024;
	/* 计算内存差值(单位:Kb) */
	int diffWorkingSetSizeKb = workingSetSizeKb - g_preWorkingSetSizeKb;
	int diffWorkSetPrivateKb = workSetPrivateKb - g_preWorkSetPrivateKb;
	int diffWorkSetSharedKb = workSetSharedKb - g_preWorkSetSharedKb;
	if (force || (unsigned int)abs(diffWorkingSetSizeKb) >= memorySize) {	/* 强制或者内存变动超过监控值 */
		/* 缓存当前内存值 */
		g_preWorkingSetSizeKb = workingSetSizeKb;
		g_preWorkSetPrivateKb = workSetPrivateKb;
		g_preWorkSetSharedKb = workSetSharedKb;
		/* Kb转Mb */
		double workingSetSizeMb = (double)workingSetSizeKb / 1024;
		double workSetPrivateMb = (double)workSetPrivateKb / 1024;
		double workSetSharedMb = (double)workSetSharedKb / 1024;
		/* 打印日志 */
		char buf[256] = { 0 };
		if (g_isInit) {	/* 首次 */
			g_isInit = false;
			sprintf_s(buf, "Memory: WorkingSet %0.1f Mb(%d Kb), Private %0.1f Mb(%d Kb), Shared %0.1f Mb(%d Kb)",
				workingSetSizeMb, workingSetSizeKb, workSetPrivateMb, workSetPrivateKb, workSetSharedMb, workSetSharedKb);
			Logger::getInstance()->print(buf, "", false, true);
			memset(buf, 0, sizeof(buf));
			sprintf_s(buf, "Handles: %d", handles);
			Logger::getInstance()->print(buf, "", false, true);
			memset(buf, 0, sizeof(buf));
			sprintf_s(buf, "Threads: %d", threads);
			Logger::getInstance()->print(buf, "", false, true);
		}
		else {	/* 非首次 */
			/* 内存差值单位Kb转Mb */
			double diffWorkingSetSizeMb = (double)diffWorkingSetSizeKb / 1024;
			double diffWorkSetPrivateMb = (double)diffWorkSetPrivateKb / 1024;
			double diffWorkSetSharedMb = (double)diffWorkSetSharedKb / 1024;
			Logger::getInstance()->print("----------------------------------------------------------------------", "", false, true);
			if (0 == diffWorkingSetSizeKb) {
				sprintf_s(buf, "                     Memory: WorkingSet %0.1f Mb(%d Kb)", workingSetSizeMb, workingSetSizeKb);
			}
			else {
				sprintf_s(buf, "                     Memory: WorkingSet %0.1f Mb(%d Kb), %s%0.1f Mb(%d Kb)",
					workingSetSizeMb, workingSetSizeKb, (diffWorkingSetSizeKb > 0 ? "+" : "-"), abs(diffWorkingSetSizeMb), abs(diffWorkingSetSizeKb));
			}
			Logger::getInstance()->print(buf, "", false, false);
			memset(buf, 0, sizeof(buf));
			if (0 == diffWorkSetPrivateKb) {
				sprintf_s(buf, "                                Private %0.1f Mb(%d Kb)", workSetPrivateMb, workSetPrivateKb);
			}
			else {
				sprintf_s(buf, "                                Private %0.1f Mb(%d Kb), %s%0.1f Mb(%d Kb)",
					workSetPrivateMb, workSetPrivateKb, (diffWorkSetPrivateKb > 0 ? "+" : "-"), abs(diffWorkSetPrivateMb), abs(diffWorkSetPrivateKb));
			}
			Logger::getInstance()->print(buf, "", false, false);
			memset(buf, 0, sizeof(buf));
			if (0 == diffWorkSetSharedKb) {
				sprintf_s(buf, "                                 Shared %0.1f Mb(%d Kb)", workSetSharedMb, workSetSharedKb);
			}
			else {
				sprintf_s(buf, "                                 Shared %0.1f Mb(%d Kb), %s%0.1f Mb(%d Kb)",
					workSetSharedMb, workSetSharedKb, (diffWorkSetSharedKb > 0 ? "+" : "-"), abs(diffWorkSetSharedMb), abs(diffWorkSetSharedKb));
			}
			Logger::getInstance()->print(buf, "", false, false);
			memset(buf, 0, sizeof(buf));
			sprintf_s(buf, "                     Handles: %d", handles);
			Logger::getInstance()->print(buf, "", false, false);
			memset(buf, 0, sizeof(buf));
			sprintf_s(buf, "                     Threads: %d", threads);
			Logger::getInstance()->print(buf, "", false, false);
		}
		/* 写入excel */
		++g_excelIndex;
		setExcelRow(g_excelIndex, workingSetSizeKb, diffWorkingSetSizeKb, workSetPrivateKb, diffWorkSetPrivateKb, workSetSharedKb, diffWorkSetSharedKb, handles, threads);
	}
	return true;
}

/* 检测输出文件名前缀中无效的字符 */
char checkInvalidPrefixChar(const std::string& prefix) {
	if (!prefix.empty()) {
		const static std::string& specialCharacters = "~!@#$%^&()_+`-={}[];',.";
		for (std::size_t i = 0, len = prefix.length(); i < len; ++i) {
			char ch = prefix.at(i);
			if (ch >= 48 && ch <= 57) {	/* 数字 */
				continue;
			}
			else if ((ch >= 65 && ch <= 90) || (ch >= 97 && ch <= 122)) {	/* 大小写字母 */
				continue;
			}
			/* 判断是否为有效的特殊字符 */
			bool isSpecialChar = false;
			for (std::size_t k = 0; k < specialCharacters.length(); ++k) {
				if (specialCharacters[k] == ch) {
					isSpecialChar = true;
					break;
				}
			}
			if (isSpecialChar) {
				continue;
			}
			/* 无效字符 */
			return ch;
		}
	}
	return '\0';
}

int main(int argc, char* argv[]) {
	/* 命令行解析 */
	cmdline::parser cl;
	cl.add<unsigned int>("pid", 'p', "process id", true);
	cl.add<unsigned int>("size", 's', "memory fluctuation size(Kb)", false, 512, cmdline::range(1, 102400)); /* 1Kb~100Mb */
	cl.add<unsigned int>("freq", 'f', "monitoring frequence(Seconds)", false, 1, cmdline::range(1, 86400));	/* 1s~1天 */
	cl.add<std::string>("prefix", 'x', "the prefix of the output filename, valid characters: [0-9][a-z][A-Z] or ~!@#$%^&()_+`-={}[];',.", false);
	cl.add("help", 0, "print this message");
	cl.set_program_name("memory_monitor");
	if (!cl.parse(argc, argv)) {
		std::cerr << cl.error() << std::endl << cl.usage();
		return 0;
	}
	if (cl.exist("help")) {
		std::cerr << cl.usage();
		return 0;
	}
	/* 进程id */
	unsigned int pid = 0;
	if (cl.exist("pid")) {
		pid = cl.get<unsigned int>("pid");
	}
	if (0 == pid)
	{
		std::cerr << "pid is 0" << std::endl << cl.usage();
		return 0;
	}
	/* 内存监控大小 */
	unsigned int size = 0;
	if (cl.exist("size")) {
		size = cl.get<unsigned int>("size");
	}
	if (0 == size)
	{
		size = 512;
	}
	/* 监控频率 */
	unsigned int freq = 0;
	if (cl.exist("freq")) {
		freq = cl.get<unsigned int>("freq");
	}
	if (0 == freq)
	{
		freq = 1;
	}
	/* 输出文件名前缀 */
	std::string prefix;
	if (cl.exist("prefix")) {
		prefix = cl.get<std::string>("prefix");
	}
	char invalidChar = checkInvalidPrefixChar(prefix);
	if ('\0' != invalidChar) {
		std::cerr << "prefix include invalid character [" << invalidChar << "]" << std::endl << cl.usage();
		return 0;
	}
	/* 生成输出文件名 */
	std::string dirname = "log/";
	if (0 != _access(dirname.c_str(), 0)) {
		if (0 != _mkdir(dirname.c_str())) {
			dirname.clear();
		}
	}
	std::string filename = dirname + prefix + "pid[" + std::to_string(pid) + "]-";
	/* 设置日志文件名 */
	std::string logFilename = filename + generateFilename(".log");
	Logger::getInstance()->setFilename(logFilename);
	/* 设置excel文件名 */
	g_excelFilename = filename + generateFilename(".xlsx");
	setExcelHeader();
	/* 打印版本号 */
	std::cout << "Version: " << VERSION << std::endl << std::endl;
	/* 打印提示 */
	std::cout << "Note: 1. you can enter 'exit' or 'quit' or 'q' to exit application !!!" << std::endl;
	std::cout << "      2. you can enter a string starting with 'tag=' to mark log sometime !!!" << std::endl;
	std::cout << "         e.g. 'tag=mytag'" << std::endl << std::endl;
	/* 打印输出文件路径 */
	char* currPath = getcwd(NULL, 0);
	std::cout << "Output:   log file => " << (currPath ? std::string(currPath) + "/" : "") << logFilename << std::endl;
	std::cout << "        excel file => " << (currPath ? std::string(currPath) + "/" : "") << g_excelFilename << std::endl << std::endl;
	if (currPath) {
		free(currPath);
	}
	/* 打印配置 */
	Logger::getInstance()->print("Start monitoring memory fluctuations", "", false, true);
	double sizeMb = (double)size / 1024;
	char buf[64] = { 0 };
	sprintf_s(buf, "memory fluctuation size: %0.1f Mb(%d Kb)", sizeMb, size);
	Logger::getInstance()->print(buf, "", false, true);
	Logger::getInstance()->print("monitoring frequency: " + std::to_string(freq) + " s", "", false, true);
	/* 创建监控线程 */
	std::thread th([&]() {
		while (1) {
			if (statisticalAnalysis(pid, size, false)) {
				std::this_thread::sleep_for(std::chrono::seconds(freq));
			}
			else {
				Logger::getInstance()->print("", "", false, false);
				Logger::getInstance()->print("Can't find process with pid[" + std::to_string(pid) + "] !!!", "", false, true);
				exit(0);
			}
		}
		});
	th.detach();
	/* 接收输入 */
	const std::string TAG = "tag=";
	std::string cmd;
	while (std::cin >> cmd)
	{
		if ("exit" == cmd || "quit" == cmd || "q" == cmd)
		{
			statisticalAnalysis(pid, size, true);
			Logger::getInstance()->print("", "", false, false);
			Logger::getInstance()->print("exit application !!!", "", false, true);
			break;
		}
		else if (TAG == cmd) {
			std::cout << "Invalid tag, missing tag name !!!" << std::endl;
		}
		else {
			std::size_t p = cmd.find(TAG);
			if (std::string::npos != p) {
				std::string tag = cmd.substr(p + TAG.length(), cmd.length() - TAG.length());
				Logger::getInstance()->print(tag, "tag", true, true);
				/* 在excel文件中, tag标记在最近一次监控记录的G列位置 */
				setExcelTag(g_excelIndex, tag);
			}
			else {
				std::cout << "Invalid command: " << cmd << " !!!" << std::endl;
			}
		}
	}
	return 0;
}
