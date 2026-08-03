// export async function POST(req: Request) {

//   const { messages } = await req.json();

//   return new Response(
//     `[stub] Recon step -> Decode step -> Candidate flag: flag{stub_placeholder}`
//   );

// }

// export async function POST(req: Request) {

//   return new Response(
// `
// Calling: identify_and_decode

// Tool args:
// {
//   "file": "challenge.png"
// }

// Tool result:
// Decoded hidden message successfully


// Calling: flag_validator

// Tool result:
// Flag format verified


// Final result:
// flag{stub_placeholder}
// `
//   );

// }


// import { streamText } from "ai";

// export async function POST(req: Request) {

//   const { messages } = await req.json();

//   const result = streamText({
//     model: "google/gemini-2.0-flash",
//     prompt:
//       "Simulate CTF agent execution. Find flag{stub_placeholder}",
//   });


//   return result.toDataStreamResponse();

// }




import { streamText } from "ai";

export async function POST(req: Request) {

  const { messages } = await req.json();

  const lastMessage =
    messages[messages.length - 1];


  const result = streamText({
    model: "google/gemini-2.0-flash",
    prompt: `
You are a CTF solving agent.

Challenge:
${lastMessage.content}

Return:
Recon step
Tool call
Result
Flag:
flag{stub_placeholder}
`,
  });


  return result.toDataStreamResponse();

}