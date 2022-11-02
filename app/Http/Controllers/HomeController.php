<?php

namespace App\Http\Controllers;

use App\Http\Controllers\API\AntrianBPJSController;
use App\Http\Controllers\API\VclaimBPJSController;
use Illuminate\Http\Request;

class HomeController extends Controller
{
    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth');
    }

    /**
     * Show the application dashboard.
     *
     * @return \Illuminate\Contracts\Support\Renderable
     */
    public function index()
    {
        return view('home');
    }
    public function status(Request $requset)
    {
        $vclaim = new VclaimBPJSController();
        $requset['nomorkartu'] = "0000067026778";
        $peserta = $vclaim->peserta_nomorkartu($requset);
        $antrian = new AntrianBPJSController();
        $poli = $antrian->ref_poli();
        return view('status', [
            "peserta" => $peserta,
            "poli" => $poli
        ]);
    }
}
