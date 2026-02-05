#include <synchapi.h>
#include <d3d11.h>
#include <dxgi.h>
#include <cstddef>
#include <cstring>
#include "libproxy_types.h"
#include "ulog.h"
#include "kiero.hpp"

#include "imgui.h"
#include "imgui_internal.h"
#include "backends/imgui_impl_win32.h"
#include "backends/imgui_impl_dx11.h"
#include "TextEditor.hpp"
#include "IconsLucide.h"
#include "lucide.ttf.hpp"

#include "gui.hpp"
#include "dll.hpp"
#include "macros.hpp"
#include "proxy_callbacks.hpp"

#define SCRIPT_EDITOR_PLACEHOLDER_TEXT ""

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace ioannes::gui {

// State

WindowState *wndState;
bool visible;

typedef long(__stdcall *Present)(IDXGISwapChain *, UINT, UINT);
Present oldPresent = NULL;

WNDPROC oldWndProc = NULL;

namespace Utils {

void DrawPaneSplitter(float *paneHeight) {
	ImVec2 avail = ImGui::GetContentRegionAvail();
	ImGui::Button("##xx", ImVec2(avail.x, 6.0f));

	bool active = ImGui::IsItemActive();
	bool hovered = ImGui::IsItemHovered();

	if (hovered || active) ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeNS);
	if (active) *paneHeight += ImGui::GetIO().MouseDelta.y;
}

}  // namespace Utils

// Main window logic stuff

// Called right after state init
void setup_proxy(void) {
	proxy_global_init(ioannes::state->fConsole, ioannes::state->logFile, ioannes::callbacks::add_log,
					  ioannes::callbacks::add_packet);
}

void state_init(void) {
	wndState = new WindowState;

	// Lua script editor

	wndState->editor.SetPalette(TextEditor::GetDarkPalette());
	wndState->editor.SetShowWhitespaces(false);
	wndState->editor.SetTabSize(4);
	wndState->editor.SetText(SCRIPT_EDITOR_PLACEHOLDER_TEXT);

	auto lang = TextEditor::LanguageDefinition::Lua();
	wndState->editor.SetLanguageDefinition(lang);

	wndState->console.AutoScroll = true;

	wndState->autoexec = false;

	// Packet log

	wndState->hexDumpEditor.ReadOnly = true;
	wndState->hexDumpEditor.OptShowDataPreview = true;
	wndState->hexDumpEditor.Cols = 26;

	wndState->isCapturing = false;
}

void draw(void) {
	// ImGui::ShowDemoWindow();

	ImGui::SetNextWindowSize(ImVec2(875, 750), ImGuiCond_Once);
	if (!ImGui::Begin("Ioannes " IOANNES_VERSION, NULL, ImGuiWindowFlags_NoScrollbar)) {
		ImGui::End();
		return;
	}

	if (ImGui::BeginTabBar("tabs", ImGuiTabBarFlags_None)) {
		if (ImGui::BeginTabItem("Scripting")) {
			static float topPaneHeight = 400.0f;
			static bool consoleOpen = true;

			wndState->editorMutex.lock();

			{
				auto topPaneSize = ImVec2(0, topPaneHeight);
				if (!consoleOpen) topPaneSize = ImVec2(0, -24);

				ImGui::BeginChild("scripting.topPane", topPaneSize, ImGuiChildFlags_None, ImGuiWindowFlags_NoScrollbar);
				wndState->editor.Render("Script Editor");
				ImGui::EndChild();
			}

			if (consoleOpen) {
				Utils::DrawPaneSplitter(&topPaneHeight);

				ImGui::BeginChild("scripting.bottomPane", ImVec2(0, -24), ImGuiChildFlags_Borders,
								  ImGuiWindowFlags_NoScrollbar);
				wndState->consoleMutex.lock();
				wndState->console.Draw();
				wndState->consoleMutex.unlock();
				ImGui::EndChild();
			}

			if (ImGui::Button(ICON_LC_PLAY " Execute")) {
				std::string editorText = wndState->editor.GetText();
				proxy_execute_script((char *)editorText.c_str());
			}

			ImGui::SameLine();
			ImGui::SeparatorEx(ImGuiSeparatorFlags_Vertical);

			ImGui::SameLine();
			ImGui::Checkbox("Autoexec", &wndState->autoexec);

			// ImGui::SameLine();
			// ImGui::SetCursorPosX(ImGui::GetCursorPosX() + ImMax(0.0f, ImGui::GetContentRegionAvail().x - 20));

			ImGui::SameLine();
			auto cpos = wndState->editor.GetCursorPosition();
			ImGui::SameLine();
			ImGui::Text("%6d:%-6d", cpos.mLine + 1, cpos.mColumn + 1);

			ImGui::SameLine();
			ImGui::Checkbox("Console", &consoleOpen);

			wndState->editorMutex.unlock();

			ImGui::EndTabItem();
		}

		if (ImGui::BeginTabItem("Packet Log")) {
			wndState->packetMutex.lock();

			static float topPaneHeight = 350.0f;
			static bool autoscroll = true;

			static ProxyPacket *selectedPkt = nullptr;
			static int selectedPktIdx = -1;

			// When filtering, we index and everything based on a separate vector
			static std::vector<ProxyPacket *> *currPktVec = &wndState->packets;
			static std::vector<ProxyPacket *> pktFilterVec;

			const char *filterTypeNames[] = {"Payload (Hex)", "Payload (ASCII)", "Packet ID"};
			static int filterType = 0;
			static char filterBuf[1024] = "";

			if (ImGui::BeginChild("packetLog.topPane", ImVec2(0, topPaneHeight), ImGuiChildFlags_None,
								  ImGuiWindowFlags_NoScrollbar)) {
				if (wndState->isCapturing) {
					if (ImGui::Button(ICON_LC_OCTAGON_PAUSE)) {
						wndState->isCapturing = false;
						proxy_set_is_capturing(0);
					}
					ImGui::SetItemTooltip("Stop capturing");
				} else {
					if (ImGui::Button(ICON_LC_PLAY)) {
						wndState->isCapturing = true;
						proxy_set_is_capturing(1);
					}
					ImGui::SetItemTooltip("Start capturing");
				}

				ImGui::SameLine();
				if (ImGui::Button(ICON_LC_TRASH_2)) {
					selectedPktIdx = -1;
					selectedPkt = nullptr;
					for (ProxyPacket *&pkt : wndState->packets) {
						proxy_packet_free(pkt);
					}
					pktFilterVec.clear();
					wndState->packets.clear();
				}
				ImGui::SetItemTooltip("Clear packet list");

				ImGui::SameLine();
				ImGui::SeparatorEx(ImGuiSeparatorFlags_Vertical);

				ImGui::SameLine();
				ImGui::Checkbox("Autoscroll", &autoscroll);

				ImGui::SameLine();
				ImGui::SeparatorEx(ImGuiSeparatorFlags_Vertical);

				ImGui::SameLine();
				ImGui::TextUnformatted("Filter");

				bool filterTypeWasChanged = false;
				ImGui::SameLine();
				if (ImGui::BeginCombo("##packetLog.filterType", filterTypeNames[filterType],
									  ImGuiComboFlags_WidthFitPreview)) {
					for (int n = 0; n < IM_ARRAYSIZE(filterTypeNames); n++) {
						const bool isSelected = (filterType == n);
						if (ImGui::Selectable(filterTypeNames[n], isSelected)) {
							filterType = n;
							filterTypeWasChanged = true;
						}

						if (isSelected) ImGui::SetItemDefaultFocus();
					}
					ImGui::EndCombo();
				}

				ImGui::SameLine();
				bool filterEntryWasChanged =
					ImGui::InputText("##packetLog.filterEntry", filterBuf, IM_ARRAYSIZE(filterBuf) - 1);
				if (filterEntryWasChanged || filterTypeWasChanged) {
					// Reset and update filter stuff
					pktFilterVec.clear();
					size_t filterBufLen = strnlen(filterBuf, sizeof(filterBuf));
					if (filterBufLen == 0) {
						currPktVec = &wndState->packets;
					} else {
						size_t decodedHexLen = 0;
						char *decodedHex = nullptr;

						switch (filterType) {
							case 0:	 // Payload (Hex)
								decodedHex = hex_str_decode(filterBuf, &decodedHexLen);
								if (decodedHex != nullptr) {
									for (ProxyPacket *&pkt : wndState->packets) {
										if (buf_contains(pkt->payload, pkt->payloadLen, decodedHex, decodedHexLen,
														 false))
											pktFilterVec.push_back(pkt);
									}

									free(decodedHex);
								}

								break;
							case 1:	 // Payload (ASCII)
								for (ProxyPacket *&pkt : wndState->packets) {
									if (buf_contains(pkt->payload, pkt->payloadLen, filterBuf, filterBufLen, true))
										pktFilterVec.push_back(pkt);
								}

								break;
							case 2:	 // Packet ID
								break;
						}

						currPktVec = &pktFilterVec;
					}
				}

				if (ImGui::BeginTable("packetLog.list", 7,
									  ImGuiTableFlags_Resizable | ImGuiTableFlags_Hideable |
										  ImGuiTableFlags_Reorderable | ImGuiTableFlags_Sortable |
										  ImGuiTableFlags_SortMulti | ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
										  ImGuiTableFlags_ScrollX | ImGuiTableFlags_ScrollY |
										  ImGuiTableFlags_SizingFixedFit)) {
					ImGui::TableSetupScrollFreeze(0, 1);  // Make top row always visible
					ImGui::TableSetupColumn("#", ImGuiTableColumnFlags_None, 60);
					ImGui::TableSetupColumn("Scope", ImGuiTableColumnFlags_None, 45);
					ImGui::TableSetupColumn("Packet", ImGuiTableColumnFlags_None, 230);
					ImGui::TableSetupColumn("Length", ImGuiTableColumnFlags_None, 60);
					ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_None, 65);
					ImGui::TableSetupColumn("Src Addr", ImGuiTableColumnFlags_None, 155);
					ImGui::TableSetupColumn("Dst Addr", ImGuiTableColumnFlags_None, 155);
					ImGui::TableHeadersRow();

					ImGuiListClipper clipper;
					clipper.Begin(currPktVec->size());
					while (clipper.Step()) {
						for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; row++) {
							ImGui::TableNextRow();
							ProxyPacket *pkt = (*currPktVec)[row];

							ImGui::TableNextColumn();

							bool isSelected = (row == selectedPktIdx);
							if (ImGui::Selectable(
									fmt::format("{}", row + 1).c_str(), isSelected,
									ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowItemOverlap)) {
								if (isSelected) {
									// selectedPktIdx = -1;
									// selectedPkt = nullptr;
								} else {
									selectedPktIdx = row;
									selectedPkt = pkt;
								}
							}

							ImGui::TableNextColumn();
							if (pkt->isSend)
								ImGui::TextUnformatted("SEND");
							else
								ImGui::TextUnformatted("RECV");

							ImGui::TableNextColumn();
							ImGui::TextUnformatted(pkt->name);

							ImGui::TableNextColumn();
							ImGui::Text("%d", pkt->payloadLen);

							ImGui::TableNextColumn();
							uint64_t t = pkt->timestamp % 86400;
							ImGui::Text("%02llu:%02llu:%02llu", t / 3600, (t / 60) % 60, t % 60);

							ImGui::TableNextColumn();
							ImGui::TextUnformatted(pkt->srcAddr);

							ImGui::TableNextColumn();
							ImGui::TextUnformatted(pkt->dstAddr);
						}
					}

					if (autoscroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) ImGui::SetScrollHereY(1.0f);

					ImGui::EndTable();
				}
			}
			ImGui::EndChild();

			Utils::DrawPaneSplitter(&topPaneHeight);

			if (ImGui::BeginTabBar("packetLog.tabs")) {
				if (ImGui::BeginTabItem("Hex Dump")) {
					if (selectedPkt != nullptr)
						wndState->hexDumpEditor.DrawContents(selectedPkt->payload, selectedPkt->payloadLen, 0);

					ImGui::EndTabItem();
				}

				ImGui::EndTabBar();
			}

			wndState->packetMutex.unlock();

			ImGui::EndTabItem();
		}

		ImGui::EndTabBar();
	}

	ImGui::End();
}

LRESULT CALLBACK wnd_proc_hook(_In_ HWND hwnd, _In_ UINT uMsg, _In_ WPARAM wParam, _In_ LPARAM lParam) {
	if (uMsg == WM_KEYDOWN && wParam == VK_INSERT) {
		visible = !visible;
		return TRUE;
	}

	if (visible) {
		if (uMsg == WM_SETCURSOR) {
			SetCursor(NULL);
			return TRUE;
		}
		ImGui_ImplWin32_WndProcHandler(hwnd, uMsg, wParam, lParam);

		auto &io = ImGui::GetIO();
		if ((io.WantCaptureMouse && (uMsg == WM_INPUT || (uMsg >= WM_MOUSEFIRST && uMsg <= WM_MOUSELAST))) ||
			(io.WantCaptureKeyboard && (uMsg >= WM_KEYFIRST && uMsg <= WM_KEYLAST)))
			return TRUE;
	}

	return CallWindowProcA(oldWndProc, hwnd, uMsg, wParam, lParam);
}

long __stdcall present_hook(IDXGISwapChain *pSwapChain, UINT SyncInterval, UINT Flags) {
	static bool presentHookInit = false;
	static ID3D11RenderTargetView *mainRenderTargetView = NULL;

	ID3D11Device *device;
	pSwapChain->GetDevice(__uuidof(ID3D11Device), (void **)&device);

	ID3D11DeviceContext *context;
	device->GetImmediateContext(&context);

	if (!presentHookInit) {
		ulog_debug("present_hook(pSwapChain: %#x, SyncInterval: %d, Flags: %#x)", pSwapChain, SyncInterval, Flags);

		state_init();
		setup_proxy();

		DXGI_SWAP_CHAIN_DESC desc;
		pSwapChain->GetDesc(&desc);

		ID3D11Texture2D *pBackBuffer = nullptr;
		pSwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), (LPVOID *)&pBackBuffer);
		device->CreateRenderTargetView(pBackBuffer, NULL, &mainRenderTargetView);
		pBackBuffer->Release();

		oldWndProc = (WNDPROC)SetWindowLongPtr(desc.OutputWindow, GWLP_WNDPROC, (uintptr_t)wnd_proc_hook);

		ImGui::CreateContext();

		auto &io = ImGui::GetIO();
		io.IniFilename = NULL;
		io.Fonts->AddFontDefault();

		float baseFontSize = 14.0f;
		static const ImWchar icons_ranges[] = {ICON_MIN_LC, ICON_MAX_16_LC, 0};
		ImFontConfig icons_config;
		icons_config.MergeMode = true;
		icons_config.PixelSnapH = true;
		icons_config.GlyphMinAdvanceX = baseFontSize;
		icons_config.GlyphOffset.y = 3.2f;
		io.Fonts->AddFontFromMemoryCompressedBase85TTF(lucide_ttf_compressed_data_base85, baseFontSize, &icons_config,
													   icons_ranges);

		ImGui_ImplWin32_Init(desc.OutputWindow);
		ImGui_ImplDX11_Init(device, context);

		presentHookInit = true;
	}

	ImGui_ImplDX11_NewFrame();
	ImGui_ImplWin32_NewFrame();
	ImGui::NewFrame();

	auto &io = ImGui::GetIO();
	if (visible) {
		io.MouseDrawCursor = true;
		draw();
	} else {
		io.MouseDrawCursor = false;
	}

	ImGui::EndFrame();
	ImGui::Render();

	context->OMSetRenderTargets(1, &mainRenderTargetView, NULL);
	ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

	return oldPresent(pSwapChain, SyncInterval, Flags);
}

void init(void) {
	ulog_info("Waiting for game window..");

	/*
	while (hwnd == nullptr) {
		hwnd = FindWindowW(L"LaunchUnrealUWindowsClient", nullptr);
		if (hwnd == nullptr) Sleep(150);
	}
	ulog_debug("HWND: %#x", hwnd);
	*/

	bool kieroInitialized = false;
	do {
		if (!kieroInitialized) {
			auto kieroInitStatus = kiero::init(kiero::RenderType::D3D11);
			ulog_debug("kieroInitStatus: %d", kieroInitStatus);
			if (kieroInitStatus != kiero::Status::Success) goto endHookLoop;
			kieroInitialized = true;
		}

		{
			auto kieroBindStatus = kiero::bind(8, (void **)&oldPresent, (void *)present_hook);
			ulog_debug("kieroBindStatus: %d", kieroBindStatus);
			if (kieroBindStatus != kiero::Status::Success) goto endHookLoop;

			break;
		}
	endHookLoop:
		Sleep(150);
	} while (!kieroInitialized);
}

}  // namespace ioannes::gui
