import type { MeasurementPolicy } from "./types.js";
import type { TdxMeasurementEntry } from "./tdxQuote.js";

interface NearPinnedMeasurement extends TdxMeasurementEntry {
  composeSha256: string;
  composeRepository: string;
  composeRepositoryCommit: string;
  composeRepositoryPath: string;
}

/** Operator-reviewed, immutable pins. Updating one of these arrays is a security
 * policy change: capture fresh evidence, cross-check the provider's provenance,
 * review every digest/register, bump the version, and deploy deliberately. */
const CHUTES_1_3_1: TdxMeasurementEntry[] = [
  {
    name: "8xh200 [v1.3.0]",
    mrTd: "ddc6efcdd2309e10837f8a7f64b71272b7ef003b129460410fe715bdfffec38c7c0c1686dddb2a23d4fd623d145e8455",
    rtmr0: "2864b11878e8129095d62a5dd7c3e3aae178d3a077606a825617324768f189ad05aed08376947df92d6c75865d915cbf",
    rtmr1: "f858ed2aecba4ecd29084352c6b5c6e403c0bec89b8c852f90fa5a8cee796ffa095518c5cd8b92c25c1856e932a95877",
    rtmr2: "7719f4fde518994a5dd6767a8b8b87a38168cc0f3480e7498d4ace99e49319be6a7fed26c21ad43310d2d488fc68ab1c",
    rtmr3: "bfac8bbe97148d00c0bc5dea273ccd926e2415511f08f5dedaa96d3c19e824d2bf01fae86e8987ff509fd3ad31374a60"
  },
  {
    name: "8xh200-r2 [v1.3.0]",
    mrTd: "ddc6efcdd2309e10837f8a7f64b71272b7ef003b129460410fe715bdfffec38c7c0c1686dddb2a23d4fd623d145e8455",
    rtmr0: "c0466500b034f7b51be7ea0fcc477e60b54833d927db96e4826ac37c60ec02dc28703a16af551f46be17035157b474da",
    rtmr1: "f858ed2aecba4ecd29084352c6b5c6e403c0bec89b8c852f90fa5a8cee796ffa095518c5cd8b92c25c1856e932a95877",
    rtmr2: "7719f4fde518994a5dd6767a8b8b87a38168cc0f3480e7498d4ace99e49319be6a7fed26c21ad43310d2d488fc68ab1c",
    rtmr3: "bfac8bbe97148d00c0bc5dea273ccd926e2415511f08f5dedaa96d3c19e824d2bf01fae86e8987ff509fd3ad31374a60"
  },
  {
    name: "8xRTX_PRO_6000 [v1.3.0]",
    mrTd: "ddc6efcdd2309e10837f8a7f64b71272b7ef003b129460410fe715bdfffec38c7c0c1686dddb2a23d4fd623d145e8455",
    rtmr0: "5064826bfd530ca9f823ceecb74899d7dbd014b60897a77317a14200c8706f2368ecbbc0a04cec8ceef90474b8c955e1",
    rtmr1: "f858ed2aecba4ecd29084352c6b5c6e403c0bec89b8c852f90fa5a8cee796ffa095518c5cd8b92c25c1856e932a95877",
    rtmr2: "7719f4fde518994a5dd6767a8b8b87a38168cc0f3480e7498d4ace99e49319be6a7fed26c21ad43310d2d488fc68ab1c",
    rtmr3: "bfac8bbe97148d00c0bc5dea273ccd926e2415511f08f5dedaa96d3c19e824d2bf01fae86e8987ff509fd3ad31374a60"
  },
  {
    name: "8xb200 [v1.3.0]",
    mrTd: "ddc6efcdd2309e10837f8a7f64b71272b7ef003b129460410fe715bdfffec38c7c0c1686dddb2a23d4fd623d145e8455",
    rtmr0: "734628b9a715ec492c2b14b409907f32d91847f439ba8bac2fa985b41c01245536348fefb2e021ed574c290c8c50347a",
    rtmr1: "f858ed2aecba4ecd29084352c6b5c6e403c0bec89b8c852f90fa5a8cee796ffa095518c5cd8b92c25c1856e932a95877",
    rtmr2: "7719f4fde518994a5dd6767a8b8b87a38168cc0f3480e7498d4ace99e49319be6a7fed26c21ad43310d2d488fc68ab1c",
    rtmr3: "bfac8bbe97148d00c0bc5dea273ccd926e2415511f08f5dedaa96d3c19e824d2bf01fae86e8987ff509fd3ad31374a60"
  },
  {
    name: "8xb200-eth [v1.3.0]",
    mrTd: "ddc6efcdd2309e10837f8a7f64b71272b7ef003b129460410fe715bdfffec38c7c0c1686dddb2a23d4fd623d145e8455",
    rtmr0: "724c1d0d20c11a479d2874fa543b0f1b920be32f2a5b9707fa5bcf6176fff31aeac9436e541e1125f78a0b61f7c2e165",
    rtmr1: "f858ed2aecba4ecd29084352c6b5c6e403c0bec89b8c852f90fa5a8cee796ffa095518c5cd8b92c25c1856e932a95877",
    rtmr2: "7719f4fde518994a5dd6767a8b8b87a38168cc0f3480e7498d4ace99e49319be6a7fed26c21ad43310d2d488fc68ab1c",
    rtmr3: "bfac8bbe97148d00c0bc5dea273ccd926e2415511f08f5dedaa96d3c19e824d2bf01fae86e8987ff509fd3ad31374a60"
  },
  {
    name: "8xb300 [v1.3.0]",
    mrTd: "ddc6efcdd2309e10837f8a7f64b71272b7ef003b129460410fe715bdfffec38c7c0c1686dddb2a23d4fd623d145e8455",
    rtmr0: "31f6446add906b7d56132c600549270a8ea780193e0c89586f784b20b25136de441ca715d5ecf86ae72f0b40f7a47f39",
    rtmr1: "f858ed2aecba4ecd29084352c6b5c6e403c0bec89b8c852f90fa5a8cee796ffa095518c5cd8b92c25c1856e932a95877",
    rtmr2: "7719f4fde518994a5dd6767a8b8b87a38168cc0f3480e7498d4ace99e49319be6a7fed26c21ad43310d2d488fc68ab1c",
    rtmr3: "bfac8bbe97148d00c0bc5dea273ccd926e2415511f08f5dedaa96d3c19e824d2bf01fae86e8987ff509fd3ad31374a60"
  },
  {
    name: "8xh200 [10.2.1] [v1.3.1]",
    mrTd: "261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d",
    rtmr0: "212d8284fe29a52a033cd662763e452915d2002bcc3c3e73aa660b100087bd3cce8aef414c3d7012f6a857f392c1919b",
    rtmr1: "9b8b2915351a3166f742024edafb6cce244c1df4056eb1f9eb608c3616b9d63729ae00c98d1dc108009c0978b19dc207",
    rtmr2: "8471360414fe80b4343fb17dd59e442bdc55b5955df0adf610b1de15ad7b454e98fb8e9d38cc188b82369f4f620b6968",
    rtmr3: "51204be641a2af357f5f4e6a121d348d6cb1cbe53c4c35d9dcc3364196b4d41a6e1de75025bb2e76f3b00cc7192f9433"
  },
  {
    name: "8xh200 [10.2.1, NVSW0] [v1.3.1]",
    mrTd: "261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d",
    rtmr0: "c90a27d633d97e2f785a0a65c4a7ee2258872655e3bada2cad0e719e313db542fd35c6889897d9ae6369f82e39877861",
    rtmr1: "9b8b2915351a3166f742024edafb6cce244c1df4056eb1f9eb608c3616b9d63729ae00c98d1dc108009c0978b19dc207",
    rtmr2: "8471360414fe80b4343fb17dd59e442bdc55b5955df0adf610b1de15ad7b454e98fb8e9d38cc188b82369f4f620b6968",
    rtmr3: "51204be641a2af357f5f4e6a121d348d6cb1cbe53c4c35d9dcc3364196b4d41a6e1de75025bb2e76f3b00cc7192f9433"
  },
  {
    name: "8xh200 [10.2.1, FLAT] [v1.3.1]",
    mrTd: "261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d",
    rtmr0: "b237753a1c8a05042209947fc0f98c8459783db7f3411860c38249c5abd4efd8c6fb7820036ff19b5099138aaf9e0bd1",
    rtmr1: "9b8b2915351a3166f742024edafb6cce244c1df4056eb1f9eb608c3616b9d63729ae00c98d1dc108009c0978b19dc207",
    rtmr2: "8471360414fe80b4343fb17dd59e442bdc55b5955df0adf610b1de15ad7b454e98fb8e9d38cc188b82369f4f620b6968",
    rtmr3: "51204be641a2af357f5f4e6a121d348d6cb1cbe53c4c35d9dcc3364196b4d41a6e1de75025bb2e76f3b00cc7192f9433"
  },
  {
    name: "8xh200 [10.1.0] [v1.3.1]",
    mrTd: "261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d",
    rtmr0: "7e76988fae31dda82f0043b331d908f0716e9da24fed80b6ea6cec9b6615ff84f24321056a8befbea3fff67bd1e59205",
    rtmr1: "9b8b2915351a3166f742024edafb6cce244c1df4056eb1f9eb608c3616b9d63729ae00c98d1dc108009c0978b19dc207",
    rtmr2: "8471360414fe80b4343fb17dd59e442bdc55b5955df0adf610b1de15ad7b454e98fb8e9d38cc188b82369f4f620b6968",
    rtmr3: "51204be641a2af357f5f4e6a121d348d6cb1cbe53c4c35d9dcc3364196b4d41a6e1de75025bb2e76f3b00cc7192f9433"
  },
  {
    name: "8xh200 [10.1.0, NVSW0] [v1.3.1]",
    mrTd: "261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d",
    rtmr0: "cdf7169a9f90c4d2fd29f89579f4ad7b90c272d607bc7ba2365e91560a248b9eafe01940f3c1e9d6bd6987573080b6c1",
    rtmr1: "9b8b2915351a3166f742024edafb6cce244c1df4056eb1f9eb608c3616b9d63729ae00c98d1dc108009c0978b19dc207",
    rtmr2: "8471360414fe80b4343fb17dd59e442bdc55b5955df0adf610b1de15ad7b454e98fb8e9d38cc188b82369f4f620b6968",
    rtmr3: "51204be641a2af357f5f4e6a121d348d6cb1cbe53c4c35d9dcc3364196b4d41a6e1de75025bb2e76f3b00cc7192f9433"
  },
  {
    name: "8xh200 [10.1.0-flat] [v1.3.1]",
    mrTd: "261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d",
    rtmr0: "ed373dfcc4e3b9cc57282773784c88445699f95705ec0995959c4aa95f9dec454c76da891fa56f820f547b02db8c1f2f",
    rtmr1: "9b8b2915351a3166f742024edafb6cce244c1df4056eb1f9eb608c3616b9d63729ae00c98d1dc108009c0978b19dc207",
    rtmr2: "8471360414fe80b4343fb17dd59e442bdc55b5955df0adf610b1de15ad7b454e98fb8e9d38cc188b82369f4f620b6968",
    rtmr3: "51204be641a2af357f5f4e6a121d348d6cb1cbe53c4c35d9dcc3364196b4d41a6e1de75025bb2e76f3b00cc7192f9433"
  },
  {
    name: "8xRTX_PRO_6000 [10.1.0] [v1.3.1]",
    mrTd: "261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d",
    rtmr0: "0917443cc41e9a5afebc8e87e69a63f32208c47d4b4b4fd410fbc1a705e1880c1383a4ad51903a5ed20cb4090420185a",
    rtmr1: "9b8b2915351a3166f742024edafb6cce244c1df4056eb1f9eb608c3616b9d63729ae00c98d1dc108009c0978b19dc207",
    rtmr2: "8471360414fe80b4343fb17dd59e442bdc55b5955df0adf610b1de15ad7b454e98fb8e9d38cc188b82369f4f620b6968",
    rtmr3: "51204be641a2af357f5f4e6a121d348d6cb1cbe53c4c35d9dcc3364196b4d41a6e1de75025bb2e76f3b00cc7192f9433"
  },
  {
    name: "8xRTX_PRO_6000 [10.2.1, NUMA2-4/4] [v1.3.1]",
    mrTd: "261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d",
    rtmr0: "5fc09d108ef74d5505b876690de5ab5da02af463ba84bb33299efd1c02144b5d7a6ba579b3ff31ef9118350468e9faf2",
    rtmr1: "9b8b2915351a3166f742024edafb6cce244c1df4056eb1f9eb608c3616b9d63729ae00c98d1dc108009c0978b19dc207",
    rtmr2: "8471360414fe80b4343fb17dd59e442bdc55b5955df0adf610b1de15ad7b454e98fb8e9d38cc188b82369f4f620b6968",
    rtmr3: "51204be641a2af357f5f4e6a121d348d6cb1cbe53c4c35d9dcc3364196b4d41a6e1de75025bb2e76f3b00cc7192f9433"
  },
  {
    name: "8xRTX_PRO_6000 [10.2.1, NUMA2-3/5] [v1.3.1]",
    mrTd: "261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d",
    rtmr0: "1de32a41a8116e042f33e9cb813f1f6edfef1452c8b2cf54df5451a848ef8931e97f40927191acabfd111c8b8d66796a",
    rtmr1: "9b8b2915351a3166f742024edafb6cce244c1df4056eb1f9eb608c3616b9d63729ae00c98d1dc108009c0978b19dc207",
    rtmr2: "8471360414fe80b4343fb17dd59e442bdc55b5955df0adf610b1de15ad7b454e98fb8e9d38cc188b82369f4f620b6968",
    rtmr3: "51204be641a2af357f5f4e6a121d348d6cb1cbe53c4c35d9dcc3364196b4d41a6e1de75025bb2e76f3b00cc7192f9433"
  },
  {
    name: "8xRTX_PRO_6000 [10.2.1, FLAT] [v1.3.1]",
    mrTd: "261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d",
    rtmr0: "e9f0b31ce30e4917767d22ad26ad0a8f4edc095b8d9f4bbb36c9cc24fe274aa2dfe16ce3c961dac2d8cef3e6ae2e901d",
    rtmr1: "9b8b2915351a3166f742024edafb6cce244c1df4056eb1f9eb608c3616b9d63729ae00c98d1dc108009c0978b19dc207",
    rtmr2: "8471360414fe80b4343fb17dd59e442bdc55b5955df0adf610b1de15ad7b454e98fb8e9d38cc188b82369f4f620b6968",
    rtmr3: "51204be641a2af357f5f4e6a121d348d6cb1cbe53c4c35d9dcc3364196b4d41a6e1de75025bb2e76f3b00cc7192f9433"
  },
  {
    name: "8xRTX_PRO_6000 [10.2.1, FLAT, MSI-GNR] [v1.3.1]",
    mrTd: "261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d",
    rtmr0: "872d965083f0bab7d080bd7d40155ba1b2b911d883f391ab7d6b9d810abeefd058e04129d72c088cf4fd05c099a57704",
    rtmr1: "9b8b2915351a3166f742024edafb6cce244c1df4056eb1f9eb608c3616b9d63729ae00c98d1dc108009c0978b19dc207",
    rtmr2: "8471360414fe80b4343fb17dd59e442bdc55b5955df0adf610b1de15ad7b454e98fb8e9d38cc188b82369f4f620b6968",
    rtmr3: "51204be641a2af357f5f4e6a121d348d6cb1cbe53c4c35d9dcc3364196b4d41a6e1de75025bb2e76f3b00cc7192f9433"
  },
  {
    name: "8xb200 [10.2.1] [v1.3.1]",
    mrTd: "261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d",
    rtmr0: "35038cbb04f872ac6d2784b05c912c438007583e58960dc66fb02d1b04462dd5994f94536da37b5877ccd3dd27d8d54d",
    rtmr1: "9b8b2915351a3166f742024edafb6cce244c1df4056eb1f9eb608c3616b9d63729ae00c98d1dc108009c0978b19dc207",
    rtmr2: "8471360414fe80b4343fb17dd59e442bdc55b5955df0adf610b1de15ad7b454e98fb8e9d38cc188b82369f4f620b6968",
    rtmr3: "51204be641a2af357f5f4e6a121d348d6cb1cbe53c4c35d9dcc3364196b4d41a6e1de75025bb2e76f3b00cc7192f9433"
  },
  {
    name: "8xb200 [10.2.1, IB4] [v1.3.1]",
    mrTd: "261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d",
    rtmr0: "555fc635cd49723dc33d53a9d53be82fd161be351174e5449a465bbeffbcbd01f36d89dcd25fad61bf4c9e65c570f5d6",
    rtmr1: "9b8b2915351a3166f742024edafb6cce244c1df4056eb1f9eb608c3616b9d63729ae00c98d1dc108009c0978b19dc207",
    rtmr2: "8471360414fe80b4343fb17dd59e442bdc55b5955df0adf610b1de15ad7b454e98fb8e9d38cc188b82369f4f620b6968",
    rtmr3: "51204be641a2af357f5f4e6a121d348d6cb1cbe53c4c35d9dcc3364196b4d41a6e1de75025bb2e76f3b00cc7192f9433"
  },
  {
    name: "8xb200 [10.2.1, XEON6] [v1.3.1]",
    mrTd: "261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d",
    rtmr0: "65fd972e40ac4d8a933d10ebfc31f07336cf1e45a3864523427b454df5d3b9dd0043f10e975da39677b62d45860c13e3",
    rtmr1: "9b8b2915351a3166f742024edafb6cce244c1df4056eb1f9eb608c3616b9d63729ae00c98d1dc108009c0978b19dc207",
    rtmr2: "8471360414fe80b4343fb17dd59e442bdc55b5955df0adf610b1de15ad7b454e98fb8e9d38cc188b82369f4f620b6968",
    rtmr3: "51204be641a2af357f5f4e6a121d348d6cb1cbe53c4c35d9dcc3364196b4d41a6e1de75025bb2e76f3b00cc7192f9433"
  },
  {
    name: "8xb200 [10.2.1, XEON6, 272CPU] [v1.3.1]",
    mrTd: "261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d",
    rtmr0: "9673907ceb0c9ca79337437bb91695e7a3d19e82df1e41de1b0d2db8081fccb5d82f26d479a5016553cb20964d5948b9",
    rtmr1: "9b8b2915351a3166f742024edafb6cce244c1df4056eb1f9eb608c3616b9d63729ae00c98d1dc108009c0978b19dc207",
    rtmr2: "8471360414fe80b4343fb17dd59e442bdc55b5955df0adf610b1de15ad7b454e98fb8e9d38cc188b82369f4f620b6968",
    rtmr3: "51204be641a2af357f5f4e6a121d348d6cb1cbe53c4c35d9dcc3364196b4d41a6e1de75025bb2e76f3b00cc7192f9433"
  },
  {
    name: "8xb200 [10.2.1, XEON6, SNC3] [v1.3.1]",
    mrTd: "261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d",
    rtmr0: "ccef43242ef633a542405dbfe55d04d823a50586b0a07510d058ea88ad8d1f8281f227f00c664435d92b23431c4d1c3c",
    rtmr1: "9b8b2915351a3166f742024edafb6cce244c1df4056eb1f9eb608c3616b9d63729ae00c98d1dc108009c0978b19dc207",
    rtmr2: "8471360414fe80b4343fb17dd59e442bdc55b5955df0adf610b1de15ad7b454e98fb8e9d38cc188b82369f4f620b6968",
    rtmr3: "51204be641a2af357f5f4e6a121d348d6cb1cbe53c4c35d9dcc3364196b4d41a6e1de75025bb2e76f3b00cc7192f9433"
  },
  {
    name: "8xb200 [10.2.1, ubuntu3] [v1.3.1]",
    mrTd: "261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d",
    rtmr0: "ff42d0f7b03cbe84f9e252d8f912b465852c8ee92584c5c047de134a46c8f1e1545683e713bbdd64e2af7d10e8bafaae",
    rtmr1: "9b8b2915351a3166f742024edafb6cce244c1df4056eb1f9eb608c3616b9d63729ae00c98d1dc108009c0978b19dc207",
    rtmr2: "8471360414fe80b4343fb17dd59e442bdc55b5955df0adf610b1de15ad7b454e98fb8e9d38cc188b82369f4f620b6968",
    rtmr3: "51204be641a2af357f5f4e6a121d348d6cb1cbe53c4c35d9dcc3364196b4d41a6e1de75025bb2e76f3b00cc7192f9433"
  },
  {
    name: "8xb300 [v1.3.1]",
    mrTd: "261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d",
    rtmr0: "91adf9667ba4c65bec5345a8c9b98010708d903847bf838c4526c3ebbc35561719e2127e48a3f6f77f651d71d2cbc8d4",
    rtmr1: "9b8b2915351a3166f742024edafb6cce244c1df4056eb1f9eb608c3616b9d63729ae00c98d1dc108009c0978b19dc207",
    rtmr2: "8471360414fe80b4343fb17dd59e442bdc55b5955df0adf610b1de15ad7b454e98fb8e9d38cc188b82369f4f620b6968",
    rtmr3: "51204be641a2af357f5f4e6a121d348d6cb1cbe53c4c35d9dcc3364196b4d41a6e1de75025bb2e76f3b00cc7192f9433"
  }
];

const NEAR_GPT_OSS_2026_08_13: NearPinnedMeasurement[] = [{
  name: "gpt-oss-120b/direct/2026-08-13",
  mrTd: "b24d3b24e9e3c16012376b52362ca09856c4adecb709d5fac33addf1c47e193da075b125b6c364115771390a5461e217",
  rtmr0: "bc122d143ab768565ba5c3774ff5f03a63c89a4df7c1f5ea38d3bd173409d14f8cbdcc36d40e703cccb996a9d9687590",
  rtmr1: "c0445b704e4c48139496ae337423ddb1dcee3a673fd5fb60a53d562f127d235f11de471a7b4ee12c9027c829786757dc",
  rtmr2: "564622c7ddc55a53272cc9f0956d29b3f7e0dd18ede432720b71fd89e5b5d76cb0b99be7b7ff2a6a92b89b6b01643135",
  rtmr3: "7fa327ff09d29f0837e9d5cace6b5d5d39f6eb80c111f57cb1b5e126be410e8f737b9e0a56f4e03a7f3fe5f211ee6d64",
  composeSha256: "fb3d47e5ae94ddfd43721002b127ce07d3828b05687e4e5a394a7a827d0ec55c",
  composeRepository: "https://github.com/nearai/cvm-compose-files",
  composeRepositoryCommit: "2390cb8cbb5b1a7dd903c702c9e5b448ebf03e88",
  composeRepositoryPath: "prod/small-models.yaml"
}];

const NEAR_GLM_2026_08_13: NearPinnedMeasurement[] = [{
  name: "glm-5.2/direct/2026-08-13",
  mrTd: "b24d3b24e9e3c16012376b52362ca09856c4adecb709d5fac33addf1c47e193da075b125b6c364115771390a5461e217",
  rtmr0: "bc122d143ab768565ba5c3774ff5f03a63c89a4df7c1f5ea38d3bd173409d14f8cbdcc36d40e703cccb996a9d9687590",
  rtmr1: "c0445b704e4c48139496ae337423ddb1dcee3a673fd5fb60a53d562f127d235f11de471a7b4ee12c9027c829786757dc",
  rtmr2: "564622c7ddc55a53272cc9f0956d29b3f7e0dd18ede432720b71fd89e5b5d76cb0b99be7b7ff2a6a92b89b6b01643135",
  rtmr3: "3738dac7d405c7dab13aa50ae54a3c9b4d8ea7964038a24d80ed46ef9d3cb1bedcbdbe35ad55bc3247b369d8c8d790b4",
  composeSha256: "db6943f37a4f54bd12144ecbf9f8c780ca14c0c44600a5a9ca09a041d92ba5ca",
  composeRepository: "https://github.com/nearai/cvm-compose-files",
  composeRepositoryCommit: "2390cb8cbb5b1a7dd903c702c9e5b448ebf03e88",
  composeRepositoryPath: "prod/small-models.yaml"
}];

export function pinnedMeasurementPolicyFor(provider: string, upstreamModel: string): MeasurementPolicy | undefined {
  if (provider === "chutes") {
    return {
      source: "https://api.chutes.ai/servers/tee/measurements",
      version: "chutes-published-full-2026-08-15",
      accepted: CHUTES_1_3_1
    };
  }
  if (provider === "near-ai" && upstreamModel === "openai/gpt-oss-120b") {
    return {
      source: "nearai/cvm-compose-files+direct-attestation",
      version: "2390cb8cbb5b1a7dd903c702c9e5b448ebf03e88/2026-08-13",
      accepted: NEAR_GPT_OSS_2026_08_13
    };
  }
  if (provider === "near-ai" && upstreamModel === "z-ai/glm-5.2") {
    return {
      source: "nearai/cvm-compose-files+direct-attestation",
      version: "2390cb8cbb5b1a7dd903c702c9e5b448ebf03e88/2026-08-13",
      accepted: NEAR_GLM_2026_08_13
    };
  }
  if (provider === "tinfoil") {
    return {
      source: "tinfoil-sdk+sigstore-transparency-log",
      version: "confidential-model-router/v0.0.140+v0.0.141/2026-08-14",
      // Immutable, additive: never edit an entry in place. The Tinfoil measurement
      // is model-agnostic (per serverURL + configRepo), so one accepted release
      // covers every Tinfoil route. Multiple entries are accepted so a release
      // rotation does not fail closed for the brief window both are in service.
      accepted: [{
        // v0.0.140 (captured 2026-08-13).
        releaseTag: "v0.0.140",
        releaseDigest: "d88c75279bb24cd0674515c477a2a9ed71334036a2df69797dcd968d2c6a238b",
        codeFingerprint: "5cd252b81bb05d773879f65e34fc591e5d5f4b1c5f2de41861beb2ee291b57487cc336d635957d8a43b98c9b500c067c",
        enclaveFingerprint: "5cd252b81bb05d773879f65e34fc591e5d5f4b1c5f2de41861beb2ee291b57487cc336d635957d8a43b98c9b500c067c"
      }, {
        // v0.0.141 (captured 2026-08-14). Reviewed by running Tinfoil's official
        // Verifier (tinfoil@1.2.1) against https://inference.tinfoil.sh with
        // configRepo tinfoilsh/confidential-model-router: securityVerified=true
        // and every step succeeded, including compareMeasurements against Tinfoil's
        // sigstore transparency log. code == enclave fingerprint (router measurement).
        releaseTag: "v0.0.141",
        releaseDigest: "7dcf6bade47993752689e9574ae6fba39ebed0fa98427329fc184558488ad8f6",
        codeFingerprint: "6d657b353726893ee7202d33efc7c849a62693049c646f9394a8c6e2a165ed9936c024c4200878927767317ba3cbca7a",
        enclaveFingerprint: "6d657b353726893ee7202d33efc7c849a62693049c646f9394a8c6e2a165ed9936c024c4200878927767317ba3cbca7a"
      }]
    };
  }
  return undefined;
}

export function pinnedEndpointIdentityFor(provider: string, upstreamModel: string): string | undefined {
  if (provider === "near-ai" && upstreamModel === "openai/gpt-oss-120b") {
    return "gpt-oss-120b.completions.near.ai";
  }
  if (provider === "near-ai" && upstreamModel === "z-ai/glm-5.2") {
    return "glm-5-2.completions.near.ai";
  }
  return undefined;
}
