"""
bot.py — Pyrph Discord Bot
===========================
Slash command: /obfuscate
  Upload a .py file → receive obfuscated .py back

Setup:
    1. pip install -r requirements.txt
    2. Copy .env.example to .env and fill in DISCORD_TOKEN
    3. python bot.py
"""
import io
import os
import tempfile
import traceback
from pathlib import Path

import discord
from discord import app_commands
from discord.ext import commands
from dotenv import load_dotenv

# ── Import Pyrph ──────────────────────────────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).parent))
from pyrph.phases.unified import build_pipeline

# ── Config ────────────────────────────────────────────────────────────────

load_dotenv()
TOKEN       = os.environ.get("DISCORD_TOKEN", "")
MAX_SIZE_KB = 512    # reject files larger than this
PROFILES    = ["fast", "balanced", "max", "stealth", "vm", "vm_max"]

# ── Bot setup ─────────────────────────────────────────────────────────────

intents = discord.Intents.default()
bot     = commands.Bot(command_prefix="!", intents=intents)
tree    = bot.tree


@bot.event
async def on_ready():
    await tree.sync()
    print(f"[Pyrph Bot] Logged in as {bot.user} | Synced slash commands")


# ── /obfuscate ────────────────────────────────────────────────────────────

@tree.command(name="obfuscate", description="Obfuscate a Python file with Pyrph")
@app_commands.describe(
    file    = "Python source file (.py)",
    profile = "Protection profile (default: balanced)",
    vm_mode = "Use C VM executor (eliminates PyEval hook — requires native compiler)",
)
@app_commands.choices(profile=[
    app_commands.Choice(name=p, value=p) for p in PROFILES
])
async def obfuscate(
    interaction: discord.Interaction,
    file:     discord.Attachment,
    profile:  app_commands.Choice[str] = None,
    vm_mode:  bool = False,
):
    prof = profile.value if profile else "balanced"

    await interaction.response.defer(thinking=True)

    # ── Validate ──────────────────────────────────────────────────────────
    if not file.filename.endswith(".py"):
        await interaction.followup.send(
            "❌ Only `.py` files are supported.", ephemeral=True)
        return

    if file.size > MAX_SIZE_KB * 1024:
        await interaction.followup.send(
            f"❌ File too large (max {MAX_SIZE_KB} KB).", ephemeral=True)
        return

    # ── Download ──────────────────────────────────────────────────────────
    try:
        raw = await file.read()
        source = raw.decode("utf-8")
    except Exception as e:
        await interaction.followup.send(f"❌ Could not read file: `{e}`", ephemeral=True)
        return

    # ── Obfuscate ─────────────────────────────────────────────────────────
    try:
        pipeline = build_pipeline(profile=prof, vm_mode=vm_mode)
        results  = pipeline.run(source)
        final    = results[-1].code

        # Build pass log
        passed  = [r for r in results if r.success]
        failed  = [r for r in results if not r.success]
        in_l    = len(source.splitlines())
        out_l   = len(final.splitlines())

        # Build embed
        embed = discord.Embed(
            title="✅ Obfuscation Complete",
            color=0x30d158,
        )
        embed.add_field(name="Profile",  value=f"`{prof}`", inline=True)
        embed.add_field(name="Passes",   value=str(len(passed)), inline=True)
        embed.add_field(name="VM Mode",  value="✓" if vm_mode else "✗", inline=True)
        embed.add_field(name="Input",    value=f"{in_l} lines", inline=True)
        embed.add_field(name="Output",   value=f"{out_l} lines", inline=True)
        embed.add_field(name="Ratio",    value=f"{out_l/max(in_l,1):.1f}x", inline=True)

        if failed:
            embed.add_field(
                name=f"⚠️ {len(failed)} pass(es) failed",
                value="\n".join(f"`{r.pass_name}` — {r.message[:80]}" for r in failed),
                inline=False,
            )

        # Attach output file
        out_bytes    = final.encode("utf-8")
        out_filename = file.filename.replace(".py", "_obf.py")
        out_file     = discord.File(
            fp=io.BytesIO(out_bytes),
            filename=out_filename,
        )

        await interaction.followup.send(embed=embed, file=out_file)

    except Exception:
        tb = traceback.format_exc()
        await interaction.followup.send(
            f"❌ Obfuscation failed:\n```\n{tb[:1800]}\n```",
            ephemeral=True,
        )


# ── /pyrph_info ───────────────────────────────────────────────────────────

@tree.command(name="pyrph_info", description="Show Pyrph engine info and available profiles")
async def pyrph_info(interaction: discord.Interaction):
    embed = discord.Embed(
        title="Pyrph — Python Obfuscation Engine",
        description="Multi-layer Python obfuscator with VM + Native C runtime",
        color=0x0a84ff,
    )
    profile_info = {
        "fast":    "Layer 1 only — surface transforms, fastest",
        "balanced":"Layer 1+2 + Native  (default)",
        "max":     "Layer 1+2 + PolyVM + Native — strongest",
        "stealth": "Balanced, reduced output size",
        "vm":      "Layer 1+2 + C VM executor (no PyEval hook)",
        "vm_max":  "All layers + C VM — maximum protection",
    }
    embed.add_field(
        name="Profiles",
        value="\n".join(f"`{k}` — {v}" for k,v in profile_info.items()),
        inline=False,
    )
    layers = [
        "**L1 Surface** — strip, rename, string vault (16-byte key), number enc, anti-debug scatter, junk",
        "**L2 AST**     — import obf, MBA, Fermat opaque predicates, CFF (random state IDs), dead code",
        "**L3 VM**      — PolyVM custom bytecode (per-build randomised opcodes)",
        "**L4 Native**  — AES-128-CTR + XOR + perm → C runtime .so (memfd, WB-key, LLVM, anti-dump)",
        "**L5 Chaos**   — visual chaos format (semicolons, unicode noise)",
    ]
    embed.add_field(name="Layers", value="\n".join(layers), inline=False)
    embed.set_footer(text="Use /obfuscate to protect your Python files")
    await interaction.response.send_message(embed=embed)


# ── /ping ─────────────────────────────────────────────────────────────────

@tree.command(name="ping", description="Check bot latency")
async def ping(interaction: discord.Interaction):
    await interaction.response.send_message(
        f"🏓 Pong! `{round(bot.latency * 1000)}ms`"
    )


# ── Run ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not TOKEN:
        print("[ERROR] DISCORD_TOKEN not set. Copy .env.example → .env and fill it in.")
        sys.exit(1)
    bot.run(TOKEN)
