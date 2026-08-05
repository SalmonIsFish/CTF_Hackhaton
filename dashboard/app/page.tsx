// // import Image from "next/image";

// // export default function Home() {
// //   return (
// //     <div className="flex flex-col flex-1 items-center justify-center bg-zinc-50 font-sans dark:bg-black">
// //       <main className="flex flex-1 w-full max-w-3xl flex-col items-center justify-between py-32 px-16 bg-white dark:bg-black sm:items-start">
// //         <Image
// //           className="dark:invert"
// //           src="/next.svg"
// //           alt="Next.js logo"
// //           width={100}
// //           height={20}
// //           priority
// //         />
// //         <div className="flex flex-col items-center gap-6 text-center sm:items-start sm:text-left">
// //           <h1 className="max-w-xs text-3xl font-semibold leading-10 tracking-tight text-black dark:text-zinc-50">
// //             To get started, edit the page.tsx file.
// //           </h1>
// //           <p className="max-w-md text-lg leading-8 text-zinc-600 dark:text-zinc-400">
// //             Looking for a starting point or more instructions? Head over to{" "}
// //             <a
// //               href="https://vercel.com/templates?framework=next.js&utm_source=create-next-app&utm_medium=appdir-template-tw&utm_campaign=create-next-app"
// //               className="font-medium text-zinc-950 dark:text-zinc-50"
// //             >
// //               Templates
// //             </a>{" "}
// //             or the{" "}
// //             <a
// //               href="https://nextjs.org/learn?utm_source=create-next-app&utm_medium=appdir-template-tw&utm_campaign=create-next-app"
// //               className="font-medium text-zinc-950 dark:text-zinc-50"
// //             >
// //               Learning
// //             </a>{" "}
// //             center.
// //           </p>
// //         </div>
// //         <div className="flex flex-col gap-4 text-base font-medium sm:flex-row">
// //           <a
// //             className="flex h-12 w-full items-center justify-center gap-2 rounded-full bg-foreground px-5 text-background transition-colors hover:bg-[#383838] dark:hover:bg-[#ccc] md:w-[158px]"
// //             href="https://vercel.com/new?utm_source=create-next-app&utm_medium=appdir-template-tw&utm_campaign=create-next-app"
// //             target="_blank"
// //             rel="noopener noreferrer"
// //           >
// //             <Image
// //               className="dark:invert"
// //               src="/vercel.svg"
// //               alt="Vercel logomark"
// //               width={16}
// //               height={16}
// //             />
// //             Deploy Now
// //           </a>
// //           <a
// //             className="flex h-12 w-full items-center justify-center rounded-full border border-solid border-black/[.08] px-5 transition-colors hover:border-transparent hover:bg-black/[.04] dark:border-white/[.145] dark:hover:bg-[#1a1a1a] md:w-[158px]"
// //             href="https://nextjs.org/docs?utm_source=create-next-app&utm_medium=appdir-template-tw&utm_campaign=create-next-app"
// //             target="_blank"
// //             rel="noopener noreferrer"
// //           >
// //             Documentation
// //           </a>
// //         </div>
// //       </main>
// //     </div>
// //   );
// // }




// "use client";

// import { useChat } from "@ai-sdk/react";

// export default function Dashboard() {
//   const { messages, input, handleInputChange, handleSubmit } = useChat({
//     api: "/api/agent",
//   });

//   return (
//     <div className="mx-auto max-w-3xl p-4">
//       <h1 className="text-xl font-bold mb-4">
//         CTF Agent — Live Trace
//       </h1>

//       {/* Challenge Input */}
//       <form onSubmit={handleSubmit} className="mb-4">
//         <textarea
//           className="w-full border p-2 rounded"
//           value={input}
//           onChange={handleInputChange}
//           placeholder="Paste challenge description, URL, or file path..."
//         />

//         <button
//           className="mt-2 bg-black text-white px-4 py-2 rounded"
//           type="submit"
//         >
//           Run Agent
//         </button>
//       </form>


//       {/* Agent Execution Trace */}
//       <div className="space-y-2">
//         {messages.map((m) => (
//           <div
//             key={m.id}
//             className="border-l-4 pl-2 text-sm"
//           >
//             <b>
//               {m.role === "user"
//                 ? "Challenge: "
//                 : "Agent step: "}
//             </b>

//             {m.content}
//           </div>
//         ))}
//       </div>


//       {/* Flag Output */}
//       <div className="mt-6 border rounded p-4">
//         <h2 className="font-bold">
//           Flag Output
//         </h2>

//         <p className="text-green-600 mt-2">
//           Waiting for agent...
//         </p>
//       </div>

//     </div>
//   );
// }




"use client";

import { useChat } from "@ai-sdk/react";
import { DefaultChatTransport } from "ai";
import { useEffect, useState } from "react";

export default function Dashboard() {
  const [input, setInput] = useState("");
  const [isRunning, setIsRunning] = useState(false);
  const [flag, setFlag] = useState("");
  // Enforce Permissions (harness element #5): when on, a live-target tool call
  // (fetch_url/tcp_open/port_scan) pauses on the backend and this dashboard renders
  // Approve/Deny controls instead of letting it fire immediately. See agent/api.py's
  // require_approval / /solve/resume for the backend half of this.
  const [requireApproval, setRequireApproval] = useState(false);

  // const {
  //   messages,
  //   input,
  //   handleInputChange,
  //   handleSubmit,
  // } = useChat({
  //   api: "/api/agent",

  //   onResponse() {
  //     setIsRunning(true);
  //     setFlag("");
  //   },

  //   onFinish(message) {
  //     setIsRunning(false);

  //     const match = message.content.match(
  //       /flag\{.*?\}/
  //     );

  //     if (match) {
  //       setFlag(match[0]);
  //     }
  //   },
  // });

    const {
    messages,
    sendMessage,
  } = useChat({
    transport: new DefaultChatTransport({ api: "/api/agent" }),

  //   onFinish(message) {
  //   setIsRunning(false);

  //   const text = message.parts
  //     .filter(part => part.type === "text")
  //     .map(part => part.text)
  //     .join("");

  //   const match = text.match(
  //     /flag\{.*?\}/
  //   );

  //   if(match){
  //     setFlag(match[0]);
  //   }
  // }


  onFinish() {
  setIsRunning(false);
},

  onError(error) {
    setIsRunning(false);
    setFlag("");
    console.error("Agent request failed:", error);
  },
  });


  // async function submitHandler(e: React.FormEvent) {
  //   e.preventDefault();
  //   setFlag("");
  //   handleSubmit(e);
  // }




    useEffect(() => {

    const lastMessage = messages[messages.length - 1];

    if (
      lastMessage &&
      lastMessage.role === "assistant"
    ) {

      // Read the backend-verified flag off a "data-flag" part (written by route.ts only when
      // agent/graph.py's observe() actually matched a flag in a real tool result), rather than
      // regexing the model's own free-text answer for anything flag-shaped. The regex approach
      // this replaced was a real, observed bug: on a challenge needing a manual byte-cipher
      // decode, the model gave up partway through and typed a fabricated flag-shaped string
      // into its prose, hedged with "(or similar instance-specific flag)" -- the backend
      // correctly never verified it (no Flag: line, no tool result matched it), but this box
      // lit up with the fabrication anyway because it never checked provenance, just shape.
      const flagPart = lastMessage.parts.find(
        (part): part is { type: "data-flag"; data: { flag: string } } => part.type === "data-flag"
      );

      if (flagPart) {
        setFlag(flagPart.data.flag);
      }

    }

  }, [messages]);

  async function submitHandler(
  e: React.FormEvent
) {
  e.preventDefault();

  setFlag("");
  setIsRunning(true);

  await sendMessage({
    text: input,
  }, {
    body: { requireApproval },
  });

  setInput("");
}


  function copyFlag() {
    navigator.clipboard.writeText(flag);
  }

  // Sends a literal "approve"/"deny" chat message -- route.ts recognizes this as a
  // response to the most recent pending-approval turn (see findPendingApproval there)
  // rather than a new challenge prompt.
  async function respondToApproval(decision: "approve" | "deny") {
    setIsRunning(true);
    await sendMessage({
      text: decision,
    }, {
      body: { requireApproval },
    });
  }


  return (
    <main className="min-h-screen bg-black text-white p-8">

      <div className="max-w-5xl mx-auto">

        <h1 className="text-4xl font-bold mb-8">
          CTF Agent — Live Trace
        </h1>


        {/* Challenge Input */}
        <form
          onSubmit={submitHandler}
          className="mb-8"
        >

          <textarea
            className="
              w-full
              h-32
              bg-gray-900
              border
              border-gray-700
              rounded
              p-4
              text-lg
            "
            value={input}
            onChange={(e)=>setInput(e.target.value)}
            placeholder="
Paste challenge description, URL, or file path...
"
          />


          <label className="mt-4 flex items-center gap-2 text-sm text-gray-300">
            <input
              type="checkbox"
              checked={requireApproval}
              onChange={(e) => setRequireApproval(e.target.checked)}
            />
            Require approval before live network calls (HITL)
          </label>

          <button
            disabled={!input.trim() || isRunning}
            className="
              mt-4
              bg-white
              text-black
              px-6
              py-3
              rounded
              font-bold
              text-lg
              disabled:opacity-50
            "
          >
            {isRunning ? "Running..." : "Run Agent"}
          </button>

        </form>


        {/* Loading */}
        {isRunning && (
          <div
            className="
              mb-6
              text-yellow-400
              text-xl
              font-bold
            "
          >
            ⚙ Agent running...
            <br/>
            Calling tools...
          </div>
        )}



        {/* Flag Box */}
        <section
          className="
            mb-8
            border
            border-green-500
            rounded
            p-6
            bg-green-950
          "
        >

          <h2
            className="
              text-3xl
              font-bold
              mb-3
            "
          >
            🚩 Flag found:
          </h2>


          {flag ? (

            <div className="flex gap-4 items-center">

              <code
                className="
                  text-2xl
                  font-bold
                  text-green-300
                "
              >
                {flag}
              </code>


              <button
                onClick={copyFlag}
                className="
                  bg-white
                  text-black
                  px-4
                  py-2
                  rounded
                "
              >
                Copy
              </button>

            </div>

          ) : (

            <p className="text-xl">
              Waiting for agent result...
            </p>

          )}

        </section>



        {/* Trace */}
        <section>

          <h2
            className="
              text-2xl
              font-bold
              mb-4
            "
          >
            Agent Execution Trace
          </h2>


          <div className="space-y-4">

            {/* {messages.map((m)=>(
              <div
                key={m.id}
                className="
                  border-l-4
                  border-blue-500
                  pl-4
                  text-lg
                "
              >

                <b>
                  {
                    m.role === "user"
                    ? "Challenge:"
                    : "Agent:"
                  }
                </b>

                <p>
                  {m.content}
                </p>

              </div>
            ))} */}


          {messages.map((m) => (
            <div
              key={m.id}
              className="
                border-l-4
                border-blue-500
                pl-4
                text-lg
              "
            >
              <b>
                {m.role === "user"
                  ? "Challenge:"
                  : "Agent:"}
              </b>

              {m.parts.map((part, index) => {
                if (part.type === "text") {
                  return <p key={index}>{part.text}</p>;
                }
                if (part.type === "data-approval") {
                  const isLatest = m.id === messages[messages.length - 1]?.id;
                  return (
                    <div key={index} className="mt-2 flex gap-3">
                      <button
                        disabled={!isLatest || isRunning}
                        onClick={() => respondToApproval("approve")}
                        className="bg-green-600 text-white px-4 py-2 rounded font-bold disabled:opacity-50"
                      >
                        Approve
                      </button>
                      <button
                        disabled={!isLatest || isRunning}
                        onClick={() => respondToApproval("deny")}
                        className="bg-red-600 text-white px-4 py-2 rounded font-bold disabled:opacity-50"
                      >
                        Deny
                      </button>
                    </div>
                  );
                }
                return null;
              })}

            </div>
          ))}
          </div>

        </section>


      </div>

    </main>
  );
}