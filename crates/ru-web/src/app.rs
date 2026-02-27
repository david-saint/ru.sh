use leptos::prelude::*;
use leptos_meta::*;
use wasm_bindgen::prelude::*;

const VERSION: &str = concat!("v", env!("CARGO_PKG_VERSION"));

/// The root component of the ru.sh landing page.
#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();
    let (is_menu_open, set_is_menu_open) = signal(false);

    view! {
        <Title text="ru.sh — Command Line Reimagined"/>
        <Meta name="description" content="Transform natural language into executable shell commands. Secure, precise, and minimal."/>

        <div class="min-h-screen bg-[#050505] text-gray-300 font-sans selection:bg-amber-500/30 selection:text-amber-200 overflow-x-hidden">
            // Background Grid Texture with subtle parallax
            <div
                class="fixed inset-0 pointer-events-none z-0 opacity-[0.015]"
                style="background-image: linear-gradient(#333 1px, transparent 1px), linear-gradient(90deg, #333 1px, transparent 1px); background-size: 60px 60px;"
            ></div>

            <Navbar is_menu_open=is_menu_open set_is_menu_open=set_is_menu_open />

            <main class="relative z-10 flex flex-col items-center">
                <HeroSection />
                <FeatureGrid />
                <HowItWorks />
                <InstallationBar />
                <Footer />
            </main>

            // Scroll Animation Observer Script
            <ScrollAnimationScript />
        </div>
    }
}

#[component]
fn Navbar(is_menu_open: ReadSignal<bool>, set_is_menu_open: WriteSignal<bool>) -> impl IntoView {
    view! {
        <nav class="fixed top-0 w-full z-50 border-b border-white/10 bg-[#050505]/80 backdrop-blur-md animate-fade-in-down">
            <div class="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
                <div class="flex items-center gap-2 group cursor-pointer magnetic-btn">
                    <div class="w-6 h-6 bg-white text-black flex items-center justify-center font-bold font-mono text-sm rounded-sm group-hover:bg-amber-500 transition-colors duration-300">
                        ">"
                    </div>
                    <span class="font-mono font-bold text-white tracking-tighter text-lg link-underline">
                        "ru.sh"
                    </span>
                </div>

                <div class="hidden md:flex items-center gap-8 font-mono text-sm">
                    <a href="#features" class="link-underline hover:text-white transition-colors duration-300">
                        "Features"
                    </a>
                    <a href="#usage" class="link-underline hover:text-white transition-colors duration-300">
                        "Usage"
                    </a>
                    <a href="https://github.com/david-saint/ru.sh" target="_blank" rel="noreferrer" class="link-underline hover:text-white transition-colors duration-300">
                        "Docs"
                    </a>
                    <a
                        href="https://github.com/david-saint/ru.sh"
                        target="_blank"
                        rel="noreferrer"
                        class="flex items-center gap-2 text-white/60 hover:text-white transition-colors duration-300 magnetic-btn"
                    >
                        <GithubIcon size=16 />
                        <span>{VERSION}</span>
                    </a>
                </div>

                {/* Mobile Menu Toggle */}
                <button
                    class="md:hidden text-white magnetic-btn"
                    on:click=move |_| set_is_menu_open.update(|v| *v = !*v)
                >
                    {move || {
                        let is_open = is_menu_open.get();
                        if is_open {
                            view! { <XIcon size=24 /> }.into_any()
                        } else {
                            view! { <MenuIcon size=24 /> }.into_any()
                        }
                    }}
                </button>
            </div>

            {/* Mobile Nav */}
            {move || is_menu_open.get().then(|| view! {
                <div class="md:hidden absolute top-16 left-0 w-full bg-[#050505] border-b border-white/10 p-6 flex flex-col gap-4 font-mono text-sm animate-fade-in-down">
                    <a href="#features" on:click=move |_| set_is_menu_open.set(false) class="hover:text-white transition-colors">
                        "Features"
                    </a>
                    <a href="#usage" on:click=move |_| set_is_menu_open.set(false) class="hover:text-white transition-colors">
                        "Usage"
                    </a>
                    <a href="https://github.com/david-saint/ru.sh" target="_blank" rel="noreferrer" on:click=move |_| set_is_menu_open.set(false) class="hover:text-white transition-colors">
                        "Docs"
                    </a>
                </div>
            })}
        </nav>
    }
}

#[component]
fn HeroSection() -> impl IntoView {
    view! {
        <section class="w-full max-w-7xl px-6 pt-32 pb-20 md:pt-48 md:pb-32 grid md:grid-cols-2 gap-16 items-center">
            <div class="space-y-8">
                <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-amber-500/20 bg-amber-500/5 text-amber-500 text-xs font-mono tracking-wide uppercase animate-fade-in-up delay-100">
                    <span class="w-2 h-2 rounded-full bg-amber-500 animate-pulse"></span>
                    "Public Beta Live"
                </div>

                <h1 class="text-5xl md:text-7xl font-bold text-white tracking-tight leading-[1.1] animate-fade-in-up delay-200">
                    "Command Line " <br />
                    <span class="text-transparent bg-clip-text bg-gradient-to-r from-gray-400 to-gray-600">
                        "Reimagined."
                    </span>
                </h1>

                <p class="text-lg md:text-xl text-gray-400 max-w-md leading-relaxed animate-fade-in-up delay-300">
                    "Stop memorizing "
                    <code class="bg-white/10 px-1 py-0.5 rounded text-gray-200 text-sm">"tar"</code>
                    " flags. Translate natural language into safe, executable shell commands instantly."
                </p>

                <div class="flex flex-col sm:flex-row gap-4 pt-4 animate-fade-in-up delay-400">
                    <a
                        href="#install"
                        class="h-12 px-8 bg-white text-black font-medium hover:bg-amber-500 transition-all duration-300 rounded-sm flex items-center justify-center gap-2 magnetic-btn group"
                    >
                        <span>"Install CLI"</span>
                        <ChevronRightIcon size=16 class="group-hover:translate-x-1 transition-transform duration-300" />
                    </a>
                    <a
                        href="https://github.com/david-saint/ru.sh"
                        target="_blank"
                        rel="noreferrer"
                        class="h-12 px-8 border border-white/20 text-white font-mono hover:bg-white/5 hover:border-white/40 transition-all duration-300 rounded-sm flex items-center justify-center gap-2 group magnetic-btn"
                    >
                        <span>"Read the docs"</span>
                        <span class="opacity-0 -ml-2 group-hover:opacity-100 group-hover:ml-0 transition-all duration-300 text-amber-500">
                            "→"
                        </span>
                    </a>
                </div>
            </div>

            <div class="relative group animate-fade-in-scale delay-500">
                <div class="absolute -inset-1 bg-gradient-to-r from-amber-500/20 to-blue-500/20 rounded-lg blur opacity-20 group-hover:opacity-40 transition duration-1000"></div>
                <TerminalSimulation />
            </div>
        </section>
    }
}

#[component]
fn TerminalSimulation() -> impl IntoView {
    let (step, set_step) = signal(0usize);
    let (cursor_visible, set_cursor_visible) = signal(true);
    let (display_text, set_display_text) = signal(String::new());
    let (command_output, set_command_output) = signal(Option::<String>::None);
    let (show_prompt, set_show_prompt) = signal(false);
    let (answer, set_answer) = signal(String::new());
    let (final_output, set_final_output) = signal(String::new());

    // Scenario data
    let scenario = vec![
        ("input", "ru -p \"archive all jpgs in current dir\"", 0),
        ("wait", "", 800),
        ("processing", "Generating command...", 0),
        ("wait", "", 600),
        ("output", "tar -cvf archive.tar *.jpg", 0),
        ("prompt", "Execute this command? [Y/n]", 0),
        ("wait", "", 1500),
        ("input_answer", "Y", 0),
        ("wait", "", 400),
        (
            "exec_output",
            "a image_01.jpg\na image_02.jpg\na image_03.jpg\nArchive created successfully.",
            0,
        ),
        ("wait", "", 3000),
        ("reset", "", 0),
    ];

    // Cursor blink effect
    Effect::new(move |_| {
        let window = web_sys::window().expect("window should exist");
        let closure = Closure::wrap(Box::new(move || {
            set_cursor_visible.update(|v| *v = !*v);
        }) as Box<dyn FnMut()>);

        let interval_id = window
            .set_interval_with_callback_and_timeout_and_arguments_0(
                closure.as_ref().unchecked_ref(),
                500,
            )
            .expect("set_interval should work");
        closure.forget();
        move || {
            window.clear_interval_with_handle(interval_id);
        }
    });

    // Scenario Runner
    Effect::new(move |_| {
        let current_step = step.get();
        if current_step >= scenario.len() {
            set_step.set(0);
            return;
        }

        let (action_type, action_text, action_ms) = scenario[current_step];
        let window = web_sys::window().expect("window should exist");

        match action_type {
            "input" => {
                let current_text = display_text.get();
                if current_text.len() < action_text.len() {
                    let next_text = action_text[..current_text.len() + 1].to_string();
                    let closure = Closure::wrap(Box::new(move || {
                        set_display_text.set(next_text.clone());
                    }) as Box<dyn FnMut()>);
                    let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
                        closure.as_ref().unchecked_ref(),
                        40,
                    );
                    closure.forget();
                } else {
                    set_step.update(|s| *s += 1);
                }
            }
            "wait" => {
                let closure = Closure::wrap(Box::new(move || {
                    set_step.update(|s| *s += 1);
                }) as Box<dyn FnMut()>);
                let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
                    closure.as_ref().unchecked_ref(),
                    action_ms,
                );
                closure.forget();
            }
            "processing" => {
                set_step.update(|s| *s += 1);
            }
            "output" => {
                set_command_output.set(Some(action_text.to_string()));
                set_step.update(|s| *s += 1);
            }
            "prompt" => {
                set_show_prompt.set(true);
                set_step.update(|s| *s += 1);
            }
            "input_answer" => {
                set_answer.set(action_text.to_string());
                set_step.update(|s| *s += 1);
            }
            "exec_output" => {
                set_final_output.set(action_text.to_string());
                set_step.update(|s| *s += 1);
            }
            "reset" => {
                set_display_text.set(String::new());
                set_command_output.set(None);
                set_show_prompt.set(false);
                set_answer.set(String::new());
                set_final_output.set(String::new());
                set_step.set(0);
            }
            _ => {}
        }
    });

    view! {
        <div class="w-full bg-[#0a0a0a] border border-white/10 rounded-md overflow-hidden font-mono text-sm shadow-2xl relative card-lift">
            // Window Controls
            <div class="h-8 bg-[#111] border-b border-white/5 flex items-center px-4 gap-2">
                <div class="w-3 h-3 rounded-full bg-red-500/20 border border-red-500/50 hover:bg-red-500/40 transition-colors cursor-pointer"></div>
                <div class="w-3 h-3 rounded-full bg-yellow-500/20 border border-yellow-500/50 hover:bg-yellow-500/40 transition-colors cursor-pointer"></div>
                <div class="w-3 h-3 rounded-full bg-green-500/20 border border-green-500/50 hover:bg-green-500/40 transition-colors cursor-pointer"></div>
                <div class="ml-auto text-xs text-white/30 tracking-widest uppercase">"user@local: ~"</div>
            </div>

            // Terminal Content
            <div class="p-6 h-[320px] flex flex-col gap-2 overflow-hidden">
                // Line 1: The Input
                <div class="flex flex-wrap">
                    <span class="text-green-500 mr-2">"➜"</span>
                    <span class="text-blue-400 mr-2">"~"</span>
                    <span class="text-gray-300 break-all">
                        {move || display_text.get()}
                        {move || {
                            let output = command_output.get();
                            let s = step.get();
                            let cursor = cursor_visible.get();
                            if output.is_none() && s < 2 && cursor {
                                view! { <span class="bg-gray-500 text-transparent inline-block w-2 h-4 align-middle ml-1 terminal-cursor">"|"</span> }.into_any()
                            } else {
                                view! { }.into_any()
                            }
                        }}
                    </span>
                </div>

                // Line 2: The Generated Command
                {move || command_output.get().map(|output| view! {
                    <div class="mt-2 pl-4 border-l-2 border-amber-500/50 bg-amber-500/5 p-3 rounded-r animate-fade-in-up">
                        <div class="text-xs text-amber-500/70 mb-1 uppercase tracking-wider">"Suggested Command"</div>
                        <code class="text-white font-bold">{output}</code>
                    </div>
                })}

                // Line 3: The Prompt
                {move || show_prompt.get().then(|| view! {
                    <div class="mt-2 animate-fade-in-up">
                        <span class="text-gray-400">"Execute this command? [Y/n] "</span>
                        <span class="text-white font-bold">{move || answer.get()}</span>
                        {move || {
                            let s = step.get();
                            let cursor = cursor_visible.get();
                            if s == 8 && cursor {
                                view! { <span class="bg-gray-500 text-transparent inline-block w-2 h-4 align-middle ml-1 terminal-cursor">"|"</span> }.into_any()
                            } else {
                                view! { }.into_any()
                            }
                        }}
                    </div>
                })}

                // Line 4: Execution Output
                {move || {
                    let output = final_output.get();
                    (!output.is_empty()).then(|| view! {
                        <div class="mt-2 text-gray-500 whitespace-pre-line animate-fade-in-up">
                            {output}
                        </div>
                    })
                }}

                // Line 5: New Line after finish
                {move || {
                    let output = final_output.get();
                    let s = step.get();
                    (!output.is_empty() && s > 9).then(|| view! {
                        <div class="mt-4 flex animate-fade-in-up">
                            <span class="text-green-500 mr-2">"➜"</span>
                            <span class="text-blue-400 mr-2">"~"</span>
                            {move || cursor_visible.get().then(|| view! {
                                <span class="bg-gray-500 text-transparent inline-block w-2 h-4 align-middle terminal-cursor">"|"</span>
                            })}
                        </div>
                    })
                }}
            </div>
        </div>
    }
}

#[component]
fn FeatureGrid() -> impl IntoView {
    view! {
        <section id="features" class="w-full max-w-7xl mx-auto px-6 py-24 border-t border-white/5">
            <div class="grid md:grid-cols-3 gap-8">
                // Feature 1
                <div class="group p-8 bg-[#0a0a0a] border border-white/5 hover:border-amber-500/30 transition-all duration-500 rounded-sm relative overflow-hidden card-lift scroll-reveal delay-100">
                    <div class="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity duration-500">
                        <ZapIcon size=64 class="icon-rotate" />
                    </div>
                    <div class="absolute inset-0 bg-gradient-to-br from-amber-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
                    <ZapIcon size=32 class="text-amber-500 mb-6 relative z-10 icon-rotate" />
                    <h3 class="text-xl font-bold text-white mb-3 relative z-10">
                        "Instant Translation"
                    </h3>
                    <p class="text-gray-400 leading-relaxed text-sm relative z-10">
                        "Powered by ultra-low latency models optimized for CLI syntax. Converts messy human thought into precise flags and arguments in milliseconds."
                    </p>
                </div>

                // Feature 2
                <div class="group p-8 bg-[#0a0a0a] border border-white/5 hover:border-blue-500/30 transition-all duration-500 rounded-sm relative overflow-hidden card-lift scroll-reveal delay-200">
                    <div class="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity duration-500">
                        <ShieldIcon size=64 class="icon-rotate" />
                    </div>
                    <div class="absolute inset-0 bg-gradient-to-br from-blue-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
                    <ShieldIcon size=32 class="text-blue-500 mb-6 relative z-10 icon-rotate" />
                    <h3 class="text-xl font-bold text-white mb-3 relative z-10">"Human in the Loop"</h3>
                    <p class="text-gray-400 leading-relaxed text-sm relative z-10">
                        "Ru.sh never executes blindly. You get a chance to review, edit, or reject the generated command. Safety is the default, not an option."
                    </p>
                </div>

                // Feature 3
                <div class="group p-8 bg-[#0a0a0a] border border-white/5 hover:border-green-500/30 transition-all duration-500 rounded-sm relative overflow-hidden card-lift scroll-reveal delay-300">
                    <div class="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity duration-500">
                        <CpuIcon size=64 class="icon-rotate" />
                    </div>
                    <div class="absolute inset-0 bg-gradient-to-br from-green-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
                    <CpuIcon size=32 class="text-green-500 mb-6 relative z-10 icon-rotate" />
                    <h3 class="text-xl font-bold text-white mb-3 relative z-10">"Context Aware"</h3>
                    <p class="text-gray-400 leading-relaxed text-sm relative z-10">
                        "Understands your current directory structure, OS version, and installed packages to generate commands that actually run on "
                        <i>"your"</i>
                        " machine."
                    </p>
                </div>
            </div>
        </section>
    }
}

#[component]
fn HowItWorks() -> impl IntoView {
    view! {
        <section id="usage" class="w-full max-w-7xl mx-auto px-6 py-24 flex flex-col items-center border-t border-white/5 bg-neutral-900/20">
            <div class="text-center max-w-2xl mb-16 scroll-reveal">
                <h2 class="text-3xl font-bold text-white mb-4">"Workflow Optimized"</h2>
                <p class="text-gray-400">
                    "Designed for flow state. Keeps your hands on the keyboard and your browser tabs closed."
                </p>
            </div>

            <div class="grid md:grid-cols-2 gap-12 w-full">
                // Steps
                <div class="space-y-12">
                    <div class="flex gap-6 scroll-reveal-left delay-100">
                        <div class="flex-shrink-0 w-12 h-12 bg-white/5 border border-white/10 flex items-center justify-center font-mono font-bold text-lg text-white group hover:border-amber-500/50 hover:bg-amber-500/10 transition-all duration-300 cursor-default">
                            "01"
                        </div>
                        <div>
                            <h4 class="text-white font-bold mb-2">"Trigger"</h4>
                            <p class="text-gray-400 text-sm">
                                "Use the global alias "
                                <code class="text-amber-500 bg-amber-500/10 px-1 rounded">"ru"</code>
                                " or map it to a hotkey. No context switching required."
                            </p>
                        </div>
                    </div>

                    <div class="flex gap-6 scroll-reveal-left delay-200">
                        <div class="flex-shrink-0 w-12 h-12 bg-white/5 border border-white/10 flex items-center justify-center font-mono font-bold text-lg text-white group hover:border-amber-500/50 hover:bg-amber-500/10 transition-all duration-300 cursor-default">
                            "02"
                        </div>
                        <div>
                            <h4 class="text-white font-bold mb-2">"Describe"</h4>
                            <p class="text-gray-400 text-sm">
                                "Type what you want in plain English. \"Kill all node processes\", \"Git commit with a message\", or \"Find duplicate files\"."
                            </p>
                        </div>
                    </div>

                    <div class="flex gap-6 scroll-reveal-left delay-300">
                        <div class="flex-shrink-0 w-12 h-12 bg-white/5 border border-white/10 flex items-center justify-center font-mono font-bold text-lg text-white group hover:border-amber-500/50 hover:bg-amber-500/10 transition-all duration-300 cursor-default">
                            "03"
                        </div>
                        <div>
                            <h4 class="text-white font-bold mb-2">"Verify & Run"</h4>
                            <p class="text-gray-400 text-sm">
                                "Review the output. Hit Enter to run, or Esc to discard. It learns your preferences over time."
                            </p>
                        </div>
                    </div>
                </div>

                // Activity Log
                <div class="bg-[#050505] border border-white/10 p-6 rounded-sm font-mono text-xs md:text-sm text-gray-400 flex flex-col justify-center card-lift scroll-reveal-right delay-200">
                    <div class="mb-4 border-b border-white/5 pb-2 text-white/30 uppercase tracking-widest">
                        "Recent Activity Log"
                    </div>
                    <div class="space-y-4">
                        <div class="flex gap-4 items-center hover:bg-white/5 p-2 -mx-2 rounded transition-colors duration-300">
                            <span class="text-white/20">"10:42:01"</span>
                            <span class="text-green-500">"SUCCESS"</span>
                            <span>
                                "converted \"undo last git commit\" -> "
                                <span class="text-gray-200">"git reset --soft HEAD~1"</span>
                            </span>
                        </div>
                        <div class="flex gap-4 items-center hover:bg-white/5 p-2 -mx-2 rounded transition-colors duration-300">
                            <span class="text-white/20">"10:45:12"</span>
                            <span class="text-green-500">"SUCCESS"</span>
                            <span>
                                "converted \"docker prune all\" -> "
                                <span class="text-gray-200">"docker system prune -a"</span>
                            </span>
                        </div>
                        <div class="flex gap-4 items-center hover:bg-white/5 p-2 -mx-2 rounded transition-colors duration-300">
                            <span class="text-white/20">"11:01:55"</span>
                            <span class="text-amber-500">"SKIPPED"</span>
                            <span>"user rejected \"rm -rf /\" (Safety Guard triggered)"</span>
                        </div>
                        <div class="flex gap-4 items-center hover:bg-white/5 p-2 -mx-2 rounded transition-colors duration-300">
                            <span class="text-white/20">"11:15:20"</span>
                            <span class="text-green-500">"SUCCESS"</span>
                            <span>
                                "converted \"check port 3000\" -> "
                                <span class="text-gray-200">"lsof -i :3000"</span>
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        </section>
    }
}

#[component]
fn InstallationBar() -> impl IntoView {
    let (copied, set_copied) = signal(false);
    // 0 = macOS/Linux, 1 = Windows
    let (platform, set_platform) = signal(0u8);

    let command = move || match platform.get() {
        0 => "curl -sL https://ru-sh.dev/install | bash",
        _ => "irm https://ru-sh.dev/install.ps1 | iex",
    };

    let handle_copy = move |_| {
        let cmd = command();
        let window = web_sys::window().expect("window should exist");
        let navigator = window.navigator();
        let clipboard = navigator.clipboard();
        let _ = clipboard.write_text(cmd);

        set_copied.set(true);

        let set_copied_clone = set_copied;
        let closure = Closure::wrap(Box::new(move || {
            set_copied_clone.set(false);
        }) as Box<dyn FnMut()>);

        let timeout_id = window
            .set_timeout_with_callback_and_timeout_and_arguments_0(
                closure.as_ref().unchecked_ref(),
                2000,
            )
            .expect("set_timeout should work");

        closure.forget();
        let _ = timeout_id;
    };

    view! {
        <section id="install" class="w-full bg-white text-black py-20 px-6 scroll-reveal-scale">
            <div class="max-w-4xl mx-auto flex flex-col md:flex-row justify-between items-center gap-8">
                <div class="text-center md:text-left scroll-reveal-left">
                    <h2 class="text-3xl font-bold mb-2 tracking-tight">
                        "Ready to ru.sh?"
                    </h2>
                    <p class="text-black/60">
                        "Open source. Privacy focused. Free for personal use."
                    </p>
                </div>

                <div class="flex flex-col items-center gap-4 scroll-reveal-right w-full max-w-lg">
                    // Platform toggle
                    <div class="flex items-center rounded-sm border border-black/10 overflow-hidden font-mono text-sm">
                        <button
                            on:click=move |_| { set_platform.set(0); set_copied.set(false); }
                            class=move || {
                                if platform.get() == 0 {
                                    "px-4 py-2 bg-black text-white font-medium transition-all duration-300"
                                } else {
                                    "px-4 py-2 bg-transparent text-black/60 hover:text-black hover:bg-black/5 transition-all duration-300"
                                }
                            }
                        >
                            "macOS / Linux"
                        </button>
                        <button
                            on:click=move |_| { set_platform.set(1); set_copied.set(false); }
                            class=move || {
                                if platform.get() == 1 {
                                    "px-4 py-2 bg-black text-white font-medium transition-all duration-300"
                                } else {
                                    "px-4 py-2 bg-transparent text-black/60 hover:text-black hover:bg-black/5 transition-all duration-300"
                                }
                            }
                        >
                            "Windows"
                        </button>
                    </div>

                    // Install command
                    <div class="flex items-center gap-4 bg-black/5 border border-black/10 rounded-sm p-2 pl-4 pr-2 hover:border-black/30 transition-all duration-300 w-full magnetic-btn">
                        <span class="font-mono text-sm md:text-base font-medium truncate">
                            {command}
                        </span>
                        <button
                            on:click=handle_copy
                            class="flex-shrink-0 p-2 bg-black text-white hover:bg-amber-500 transition-all duration-300 rounded-sm ml-auto magnetic-btn"
                        >
                            {move || {
                                let is_copied = copied.get();
                                if is_copied {
                                    view! { <CheckIcon size=18 /> }.into_any()
                                } else {
                                    view! { <CopyIcon size=18 /> }.into_any()
                                }
                            }}
                        </button>
                    </div>

                    // Shell hint
                    <p class="text-black/40 text-xs font-mono">
                        {move || match platform.get() {
                            0 => "Run in your terminal (bash, zsh, or sh)",
                            _ => "Run in PowerShell as Administrator",
                        }}
                    </p>
                </div>
            </div>
        </section>
    }
}

#[component]
fn Footer() -> impl IntoView {
    view! {
        <footer class="w-full max-w-7xl px-6 py-12 border-t border-white/5 flex flex-col md:flex-row justify-between items-center gap-6 text-sm text-gray-500 font-mono animate-fade-in-up">
            <div class="flex items-center gap-2">
                <div class="w-4 h-4 bg-white/10 flex items-center justify-center text-[10px] text-white hover:bg-amber-500/50 transition-colors duration-300">
                    "R"
                </div>
                <span>"ru.sh © 2026"</span>
            </div>

            <div class="flex gap-8">
                <a href="#" class="link-underline hover:text-white transition-colors duration-300">
                    "Privacy"
                </a>
                <a href="#" class="link-underline hover:text-white transition-colors duration-300">
                    "Terms"
                </a>
                <a href="#" class="link-underline hover:text-white transition-colors duration-300">
                    "Twitter"
                </a>
                <a href="https://github.com/david-saint/ru.sh" target="_blank" rel="noreferrer" class="link-underline hover:text-white transition-colors duration-300">
                    "GitHub"
                </a>
            </div>
        </footer>
    }
}

// Unified Icon Component
#[component]
fn Icon(name: &'static str, size: u32, #[prop(optional)] class: &'static str) -> impl IntoView {
    match name {
        "zap" => view! {
            <svg
                xmlns="http://www.w3.org/2000/svg"
                width=size
                height=size
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
                class=class
            >
                <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
            </svg>
        }.into_any(),
        "shield" => view! {
            <svg
                xmlns="http://www.w3.org/2000/svg"
                width=size
                height=size
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
                class=class
            >
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
        }.into_any(),
        "cpu" => view! {
            <svg
                xmlns="http://www.w3.org/2000/svg"
                width=size
                height=size
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
                class=class
            >
                <rect x="4" y="4" width="16" height="16" rx="2" ry="2" />
                <rect x="9" y="9" width="6" height="6" />
                <line x1="9" y1="1" x2="9" y2="4" />
                <line x1="15" y1="1" x2="15" y2="4" />
                <line x1="9" y1="20" x2="9" y2="23" />
                <line x1="15" y1="20" x2="15" y2="23" />
                <line x1="20" y1="9" x2="23" y2="9" />
                <line x1="20" y1="14" x2="23" y2="14" />
                <line x1="1" y1="9" x2="4" y2="9" />
                <line x1="1" y1="14" x2="4" y2="14" />
            </svg>
        }.into_any(),
        "github" => view! {
            <svg
                xmlns="http://www.w3.org/2000/svg"
                width=size
                height=size
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
                class=class
            >
                <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" />
            </svg>
        }.into_any(),
        "chevron-right" => view! {
            <svg
                xmlns="http://www.w3.org/2000/svg"
                width=size
                height=size
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
                class=class
            >
                <polyline points="9 18 15 12 9 6" />
            </svg>
        }.into_any(),
        "copy" => view! {
            <svg
                xmlns="http://www.w3.org/2000/svg"
                width=size
                height=size
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
                class=class
            >
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
            </svg>
        }.into_any(),
        "check" => view! {
            <svg
                xmlns="http://www.w3.org/2000/svg"
                width=size
                height=size
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
                class=class
            >
                <polyline points="20 6 9 17 4 12" />
            </svg>
        }.into_any(),
        "menu" => view! {
            <svg
                xmlns="http://www.w3.org/2000/svg"
                width=size
                height=size
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
                class=class
            >
                <line x1="3" y1="12" x2="21" y2="12" />
                <line x1="3" y1="6" x2="21" y2="6" />
                <line x1="3" y1="18" x2="21" y2="18" />
            </svg>
        }.into_any(),
        "x" => view! {
            <svg
                xmlns="http://www.w3.org/2000/svg"
                width=size
                height=size
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
                class=class
            >
                <line x1="18" y1="6" x2="6" y2="18" />
                <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
        }.into_any(),
        _ => view! { <svg width=size height=size></svg> }.into_any(),
    }
}

// Individual Icon Components (for direct use)
#[component]
fn GithubIcon(size: u32) -> impl IntoView {
    view! { <Icon name="github" size=size /> }
}

#[component]
fn ChevronRightIcon(size: u32, #[prop(optional)] class: &'static str) -> impl IntoView {
    view! { <Icon name="chevron-right" size=size class=class /> }
}

#[component]
fn CopyIcon(size: u32) -> impl IntoView {
    view! { <Icon name="copy" size=size /> }
}

#[component]
fn CheckIcon(size: u32) -> impl IntoView {
    view! { <Icon name="check" size=size /> }
}

#[component]
fn MenuIcon(size: u32) -> impl IntoView {
    view! { <Icon name="menu" size=size /> }
}

#[component]
fn XIcon(size: u32) -> impl IntoView {
    view! { <Icon name="x" size=size /> }
}

#[wasm_bindgen::prelude::wasm_bindgen(inline_js = r#"
    export function init_scroll_animations() {
        const elements = document.querySelectorAll('.scroll-reveal, .scroll-reveal-left, .scroll-reveal-right, .scroll-reveal-scale');
        
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('scroll-revealed');
                }
            });
        }, {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        });
        
        elements.forEach(el => observer.observe(el));
    }
"#)]
extern "C" {
    fn init_scroll_animations();
}

#[component]
fn ScrollAnimationScript() -> impl IntoView {
    Effect::new(move |_| {
        let window = web_sys::window().expect("window should exist");

        let closure = Closure::wrap(Box::new(move || {
            init_scroll_animations();
        }) as Box<dyn FnMut()>);

        let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
            closure.as_ref().unchecked_ref(),
            100,
        );
        closure.forget();
    });

    view! {}
}

#[component]
fn ZapIcon(size: u32, #[prop(optional)] class: &'static str) -> impl IntoView {
    view! { <Icon name="zap" size=size class=class /> }
}

#[component]
fn ShieldIcon(size: u32, #[prop(optional)] class: &'static str) -> impl IntoView {
    view! { <Icon name="shield" size=size class=class /> }
}

#[component]
fn CpuIcon(size: u32, #[prop(optional)] class: &'static str) -> impl IntoView {
    view! { <Icon name="cpu" size=size class=class /> }
}
