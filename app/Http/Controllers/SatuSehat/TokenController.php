<?php

namespace App\Http\Controllers\SatuSehat;

use App\Http\Controllers\Controller;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Session;
use RealRashid\SweetAlert\Facades\Alert;

class TokenController extends Controller
{
    public function status()
    {
        return view('satusehat.status');
    }
    public function refresh_token()
    {
        $response = $this->token();
        if ($response->status() == 200) {
            Alert::success($response->statusText());
        } else {
            Alert::error($response->statusText().' '. $response->status());
        }
        return redirect()->route('satusehat.status');
    }
    // API SATU SEHAT
    public function token()
    {
        $url =  env('SATUSEHAT_AUTH_URL') . "/accesstoken?grant_type=client_credentials";
        $response = Http::asForm()->post($url, [
            'client_id' => env('SATUSEHAT_CLIENT_ID'),
            'client_secret' => env('SATUSEHAT_SECRET_ID'),
        ]);
        if ($response->successful()) {
            $json = json_decode($response);
            Session::put('tokenSatuSehat', $json->access_token);
            Session::put('TimestampSatuSehat', Carbon::now());
            Log::notice('Auth Token Satu Sehat : ' . $json->access_token);
        }
        return response()->json($response->json(), $response->status());
    }
}
