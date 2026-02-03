use leptos::prelude::*;
use leptos_meta::*;

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();

    view! {
        <Title text="ru.sh - Natural Language to Bash"/>
        <Meta name="description" content="Convert natural language to bash scripts instantly. Secure, fast, and powered by AI."/>

        <main class="container">
            <Hero/>
            <Features/>
            <Usage/>
            <Installation/>
            <Footer/>
        </main>
    }
}

#[component]
fn Hero() -> impl IntoView {
    view! {
        <section class="hero">
            <h1>"ru.sh"</h1>
            <p class="tagline">"Natural Language → Bash Scripts"</p>
            <p class="description">
                "Transform your ideas into shell commands instantly. "
                "Secure, fast, and powered by AI."
            </p>
            <div class="cta">
                <code>"cargo install ru-cli"</code>
            </div>
        </section>
    }
}

#[component]
fn Features() -> impl IntoView {
    view! {
        <section class="features">
            <h2>"Why ru.sh?"</h2>
            <div class="feature-grid">
                <div class="feature">
                    <h3>"⚡ Lightning Fast"</h3>
                    <p>"Automatically selects the fastest available AI model for instant script generation."</p>
                </div>
                <div class="feature">
                    <h3>"🔒 Security First"</h3>
                    <p>"Review every script before execution. Never runs anything without your explicit approval."</p>
                </div>
                <div class="feature">
                    <h3>"🧠 Smart Generation"</h3>
                    <p>"Powered by OpenRouter, accessing the best coding models available."</p>
                </div>
                <div class="feature">
                    <h3>"💬 Explain Mode"</h3>
                    <p>"Don't understand a script? Ask for an explanation before running."</p>
                </div>
            </div>
        </section>
    }
}

#[component]
fn Usage() -> impl IntoView {
    view! {
        <section class="usage">
            <h2>"Usage"</h2>
            <div class="example">
                <p class="prompt">"Rename all images to person-1.jpg, person-2.png, etc."</p>
                <pre><code>r#"ru -p "Rename all the images in this folder to person-${i}.{ext}""#</code></pre>
            </div>
            <div class="example">
                <p class="prompt">"Find large files eating up disk space"</p>
                <pre><code>r#"ru -p "Find all files larger than 100MB and sort by size""#</code></pre>
            </div>
            <div class="example">
                <p class="prompt">"Quick git workflow"</p>
                <pre><code>r#"ru -p "Stage all changes, commit with message 'fix typo', and push""#</code></pre>
            </div>
        </section>
    }
}

#[component]
fn Installation() -> impl IntoView {
    view! {
        <section class="installation">
            <h2>"Get Started"</h2>
            <ol>
                <li>
                    <strong>"Install ru.sh"</strong>
                    <pre><code>"cargo install ru-cli"</code></pre>
                </li>
                <li>
                    <strong>"Set your OpenRouter API key"</strong>
                    <pre><code>"export OPENROUTER_API_KEY=your_key_here"</code></pre>
                </li>
                <li>
                    <strong>"Start using natural language"</strong>
                    <pre><code>r#"ru -p "your command in plain English""#</code></pre>
                </li>
            </ol>
        </section>
    }
}

#[component]
fn Footer() -> impl IntoView {
    view! {
        <footer>
            <p>"Built with 🦀 Rust"</p>
            <p>
                <a href="https://github.com/saint/ru.sh">"GitHub"</a>
                " · "
                <a href="https://openrouter.ai">"Powered by OpenRouter"</a>
            </p>
        </footer>
    }
}
