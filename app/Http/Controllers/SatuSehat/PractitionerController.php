<?php

namespace App\Http\Controllers\SatuSehat;

use App\Http\Controllers\Controller;
use App\Models\SIMRS\Token;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Facades\Validator;
use RealRashid\SweetAlert\Facades\Alert;

class PractitionerController extends Controller
{
    public function index(Request $request)
    {
        $practitioner = null;
        if (isset($request->nik)) {
            $response = $this->practitioner_by_nik($request->nik);
            $data = $response->getData();
            if ($response->status() == 200) {
                if ($data->total) {
                    $practitioner = $data->entry[0]->resource;
                    Alert::success($response->statusText(), 'Practitioner Ditemukan');
                } else {
                    Alert::error('Not Found', 'Practitioner Tidak Ditemukan');
                }
            } else {
                Alert::error($response->statusText() . ' ' . $response->status());
            }
        }
        if (isset($request->id)) {
            $response = $this->practitioner_by_id($request->id);
            $data = $response->getData();
            if ($response->status() == 200) {
                if ($data->resourceType == "Practitioner") {
                    $practitioner = $data;
                    Alert::success($response->statusText(), ' Practitioner Ditemukan');
                } else {
                    Alert::error('Not Found', 'Practitioner Tidak Ditemukan');
                }
            } else {
                Alert::error($response->statusText() . ' ' . $response->status());
            }
        }
        return view('satusehat.practitioner', compact([
            'request',
            'practitioner'
        ]));
    }
    // API SATU SEHAT
    public function practitioner_by_nik($nik)
    {
        $token = Token::latest()->first()->access_token;
        $url =  env('SATUSEHAT_BASE_URL') . "/Practitioner?identifier=https://fhir.kemkes.go.id/id/nik|" . $nik;
        $response = Http::withToken($token)->get($url);
        if ($response->status() == 401) {
            $refresh_token = new TokenController();
            $refresh_token->token();
        }
        return response()->json($response->json(), $response->status());
    }
    public function practitioner_by_name(Request $request)
    {
        $validator = Validator::make(request()->all(), [
            "birthdate" => "required",
            "gender" => "required",
            "name" => "required",
        ]);
        if ($validator->fails()) {
            return $this->sendError('Data Belum Lengkap', $validator->errors()->first(), 400);
        }
        $token = Token::latest()->first()->access_token;
        $url =  env('SATUSEHAT_BASE_URL') . "/Practitioner?name=" . $request->name . "&birthdate=" . $request->birthdate . "&gender=" . $request->gender;
        $response = Http::withToken($token)->get($url);
        if ($response->status() == 401) {
            $refresh_token = new TokenController();
            $refresh_token->token();
        }
        return response()->json($response->json(), $response->status());
    }
    public function practitioner_by_id($id)
    {
        $token = Token::latest()->first()->access_token;
        $url =  env('SATUSEHAT_BASE_URL') . "/Practitioner/" . $id;
        $response = Http::withToken($token)->get($url);
        if ($response->status() == 401) {
            $refresh_token = new TokenController();
            $refresh_token->token();
        }
        return response()->json($response->json(), $response->status());
    }
}
