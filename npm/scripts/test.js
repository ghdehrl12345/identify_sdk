const { init } = require("../index.js");

async function test() {
    console.log("🧪 Running identify-sdk smoke test...\n");

    try {
        const client = await init();
        console.log("✅ SDK initialized successfully");

        // Generate a test salt (in real usage, server provides this)
        const salt = "deadbeefdeadbeef";

        // Generate proof
        const result = client.generateProof(
            "testpassword",  // secret
            2000,            // birth year
            { targetYear: 2025, limitAge: 20 },
            12345,           // challenge
            salt
        );

        console.log("✅ Proof generated:");
        console.log("   proof length:", result.proof.length, "chars");
        console.log("   hash:", result.hash.substring(0, 20) + "...");
        console.log("   binding:", result.binding.substring(0, 20) + "...");

        console.log("\n✅ All tests passed!");
        process.exit(0);
    } catch (err) {
        console.error("❌ Test failed:", err.message);
        process.exit(1);
    }
}

test();
